"""Tests for the Aegis web layer: auth, rate limiting, headers, validation."""

import os

import pytest
from fastapi.testclient import TestClient

from aegis.web.security import (AuthLockout, RateLimiter, SecurityHeadersMiddleware,
                                check_token, load_or_create_token)
from aegis.web.server import create_app


@pytest.fixture()
def token_path(tmp_path):
    return tmp_path / "api_token"


@pytest.fixture()
def client(token_path, tmp_path, monkeypatch):
    # Isolate AEGIS_HOME so the app never touches the real one.
    monkeypatch.setattr("aegis.web.server.AEGIS_HOME", tmp_path / "aegis_home")
    app = create_app(token_path=token_path)
    return TestClient(app)


def _token(token_path):
    return token_path.read_text().strip()


class TestTokenManagement:
    def test_token_created_with_strict_perms(self, token_path):
        token = load_or_create_token(token_path)
        assert len(token) == 64  # 256 bits hex
        assert oct(os.stat(token_path).st_mode & 0o777) == "0o600"
        # second call returns the same token
        assert load_or_create_token(token_path) == token

    def test_corrupt_token_rejected(self, token_path):
        token_path.write_text("short")
        with pytest.raises(RuntimeError):
            load_or_create_token(token_path)

    def test_constant_time_compare(self):
        assert check_token("a" * 64, "a" * 64)
        assert not check_token("a" * 64, "b" * 64)
        assert not check_token("short", "a" * 64)


class TestAuth:
    def test_unauthenticated_rejected(self, client):
        assert client.get("/api/alerts").status_code == 401
        assert client.get("/api/stats").status_code == 401
        assert client.post("/api/scan").status_code == 401

    def test_wrong_token_rejected(self, client):
        r = client.get("/api/alerts", headers={"Authorization": "Bearer wrong" * 8})
        assert r.status_code == 401

    def test_correct_token_accepted(self, client, token_path):
        r = client.get("/api/alerts",
                       headers={"Authorization": f"Bearer {_token(token_path)}"})
        assert r.status_code == 200

    def test_lockout_after_repeated_failures(self, client, token_path):
        for _ in range(5):
            client.get("/api/alerts", headers={"Authorization": "Bearer wrong" * 8})
        # now even the *correct* token is refused for this client
        r = client.get("/api/alerts",
                       headers={"Authorization": f"Bearer {_token(token_path)}"})
        assert r.status_code == 429


class TestRateLimiterAndLockout:
    def test_rate_limiter_window(self):
        rl = RateLimiter(max_requests=3, window_seconds=60)
        assert all(rl.allow("1.2.3.4") for _ in range(3))
        assert not rl.allow("1.2.3.4")
        assert rl.allow("5.6.7.8")  # other clients unaffected

    def test_lockout_unit(self):
        lock = AuthLockout(max_failures=2, lockout_seconds=60)
        lock.record_failure("ip")
        assert not lock.is_locked("ip")
        lock.record_failure("ip")
        assert lock.is_locked("ip")
        lock.record_success("ip")
        assert not lock.is_locked("ip")


class TestSecurityHeaders:
    def test_headers_on_api(self, client):
        r = client.get("/")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert "script-src 'self'" in r.headers["Content-Security-Policy"]
        assert r.headers["Cache-Control"] == "no-store"
        assert "server" not in {k.lower() for k in r.headers}

    def test_no_api_schema_exposed(self, client):
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/docs").status_code == 404


class TestEndpoints:
    def auth(self, token_path):
        return {"Authorization": f"Bearer {_token(token_path)}"}

    def test_static_traversal_blocked(self, client):
        assert client.get("/static/../server.py").status_code == 404
        assert client.get("/static/.secret").status_code == 404

    def test_ioc_validation(self, client, token_path):
        r = client.post("/api/iocs", headers=self.auth(token_path),
                        json={"category": "ip", "value": "bad value with spaces"})
        assert r.status_code == 422
        r = client.post("/api/iocs", headers=self.auth(token_path),
                        json={"category": "bogus", "value": "1.2.3.4"})
        assert r.status_code == 422

    def test_ioc_add_list_remove(self, client, token_path):
        h = self.auth(token_path)
        assert client.post("/api/iocs", headers=h,
                           json={"category": "ip", "value": "203.0.113.7"}).status_code == 201
        data = client.get("/api/iocs", headers=h).json()
        assert "203.0.113.7" in data["ip"]
        client.request("DELETE", "/api/iocs", headers=h,
                       json={"category": "ip", "value": "203.0.113.7"})
        data = client.get("/api/iocs", headers=h).json()
        assert "203.0.113.7" not in data.get("ip", [])

    def test_bad_severity_filter(self, client, token_path):
        r = client.get("/api/alerts?severity=apocalyptic", headers=self.auth(token_path))
        assert r.status_code == 422

    def test_fim_check_rejects_missing_dir(self, client, token_path):
        r = client.post("/api/fim/check?directory=/nonexistent-xyz",
                        headers=self.auth(token_path))
        assert r.status_code == 422
