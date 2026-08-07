"""Tests for multi-user accounts: Argon2id hashing, roles, audit log."""

import json
import os
import re

import pytest
from fastapi.testclient import TestClient

from aegis.web.auth import MIN_PASSWORD_LENGTH, UserStore, generate_password
from aegis.web.audit import load_events, log_event
from aegis.web.server import create_app


@pytest.fixture()
def store(tmp_path):
    return UserStore(tmp_path / "users.json")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("aegis.web.server.AEGIS_HOME", tmp_path / "aegis_home")
    app = create_app(token_path=tmp_path / "api_token")
    return TestClient(app), UserStore(tmp_path / "aegis_home" / "users.json")


GOOD_PW = "correct horse battery"  # 22 chars


class TestUserStore:
    def test_add_and_verify(self, store):
        store.add_user("alice", GOOD_PW, "admin")
        assert store.verify("alice", GOOD_PW).role == "admin"
        assert store.verify("alice", "wrong password here") is None
        assert store.verify("mallory", GOOD_PW) is None

    def test_hash_is_argon2id_and_file_perms(self, store, tmp_path):
        store.add_user("alice", GOOD_PW, "analyst")
        data = json.loads((tmp_path / "users.json").read_text())
        assert data["alice"]["pw"].startswith("$argon2id$")
        assert GOOD_PW not in json.dumps(data)  # plaintext never stored
        assert oct(os.stat(tmp_path / "users.json").st_mode & 0o777) == "0o600"

    def test_duplicate_rejected(self, store):
        store.add_user("alice", GOOD_PW, "admin")
        with pytest.raises(ValueError):
            store.add_user("alice", GOOD_PW + "x", "admin")

    def test_short_password_rejected(self, store):
        with pytest.raises(ValueError):
            store.add_user("alice", "tooshort", "admin")

    def test_bad_username_rejected(self, store):
        with pytest.raises(ValueError):
            store.add_user("al ice", GOOD_PW, "admin")
        with pytest.raises(ValueError):
            store.add_user("ab", GOOD_PW, "admin")

    def test_bad_role_rejected(self, store):
        with pytest.raises(ValueError):
            store.add_user("alice", GOOD_PW, "superuser")

    def test_last_admin_protected(self, store):
        store.add_user("solo", GOOD_PW, "admin")
        with pytest.raises(ValueError):
            store.remove_user("solo")
        store.add_user("backup", GOOD_PW, "admin")
        store.remove_user("solo")  # now fine
        assert store.get("solo") is None

    def test_change_password(self, store):
        store.add_user("alice", GOOD_PW, "admin")
        store.change_password("alice", "new password phrase")
        assert store.verify("alice", GOOD_PW) is None
        assert store.verify("alice", "new password phrase") is not None

    def test_generated_password_meets_policy(self):
        pw = generate_password()
        assert len(pw) >= MIN_PASSWORD_LENGTH


class TestAudit:
    def test_roundtrip(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log_event(path, "alice", "login", "")
        log_event(path, "alice", "user_add", "bob")
        events = load_events(path)
        assert [e["action"] for e in events] == ["user_add", "login"]  # newest first
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


class TestMultiUserWeb:
    def _login(self, c, username, password, expect=303):
        r = c.post("/login", data={"username": username, "password": password},
                   follow_redirects=False)
        assert r.status_code == expect
        return r.cookies

    def _csrf(self, c, cookies):
        r = c.get("/console", cookies=cookies)
        assert r.status_code == 200
        return re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)

    def test_token_mode_when_no_users(self, client):
        c, users = client
        r = c.get("/")
        assert "API token" in r.text  # token form shown

    def test_user_mode_when_users_exist(self, client):
        c, users = client
        users.add_user("admin1", GOOD_PW, "admin")
        r = c.get("/")
        assert "Username" in r.text and "Password" in r.text

    def test_login_flow_and_identity_shown(self, client):
        c, users = client
        users.add_user("admin1", GOOD_PW, "admin")
        cookies = self._login(c, "admin1", GOOD_PW)
        r = c.get("/console", cookies=cookies)
        assert "admin1 (admin)" in r.text
        assert "Users" in r.text  # admin panel visible

    def test_wrong_password_rejected_and_audited(self, client, tmp_path):
        c, users = client
        users.add_user("admin1", GOOD_PW, "admin")
        self._login(c, "admin1", "wrong password!!", expect=401)
        audit_file = tmp_path / "aegis_home" / "audit.jsonl"
        events = load_events(audit_file)
        assert any(e["action"] == "login_failed" and e["user"] == "admin1"
                   for e in events)

    def test_audit_written_on_login(self, client, tmp_path):
        c, users = client
        users.add_user("admin1", GOOD_PW, "admin")
        self._login(c, "admin1", GOOD_PW)
        audit_file = tmp_path / "aegis_home" / "audit.jsonl"
        events = load_events(audit_file)
        assert any(e["action"] == "login" and e["user"] == "admin1" for e in events)

    def test_analyst_cannot_manage_users(self, client):
        c, users = client
        users.add_user("admin1", GOOD_PW, "admin")
        users.add_user("an1", GOOD_PW, "analyst")
        cookies = self._login(c, "an1", GOOD_PW)
        r = c.get("/console", cookies=cookies)
        assert "an1 (analyst)" in r.text
        assert "Add" in r.text  # IOC panel still there
        assert "Audit log" not in r.text  # admin panels hidden
        csrf = self._csrf(c, cookies)
        r = c.post("/ui/users/add", cookies=cookies,
                   data={"csrf": csrf, "username": "mallory", "password": GOOD_PW,
                         "role": "admin"})
        assert r.status_code == 403

    def test_admin_can_add_and_remove_users_via_ui(self, client):
        c, users = client
        users.add_user("admin1", GOOD_PW, "admin")
        cookies = self._login(c, "admin1", GOOD_PW)
        csrf = self._csrf(c, cookies)
        r = c.post("/ui/users/add", cookies=cookies,
                   data={"csrf": csrf, "username": "bob7", "password": GOOD_PW,
                         "role": "analyst"}, follow_redirects=False)
        assert r.status_code == 303
        assert users.get("bob7") is not None
        r = c.post("/ui/users/remove", cookies=cookies,
                   data={"csrf": csrf, "username": "bob7"}, follow_redirects=False)
        assert r.status_code == 303
        assert users.get("bob7") is None
