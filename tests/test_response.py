"""Tests for active response: kill, quarantine, block, rule wiring."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from pathlib import Path

import psutil
import pytest

from aegis.agent import Agent
from aegis.alerts import AlertSink
from aegis.detection.engine import DetectionEngine, Rule
from aegis.response.actions import (
    DEFAULT_QUARANTINE_DIR, Responder, VALID_RESPONSES,
)


@pytest.fixture
def responder(tmp_path):
    return Responder(log_path=tmp_path / "response.jsonl",
                     quarantine_dir=tmp_path / "vault",
                     blocked_path=tmp_path / "blocked.json",
                     dry_run=True)


class TestKillProcess:
    def test_kill_real_process(self, tmp_path):
        proc = subprocess.Popen(["sleep", "300"])
        try:
            r = Responder(log_path=tmp_path / "r.jsonl",
                          quarantine_dir=tmp_path / "v", dry_run=False)
            result = r.kill_process(proc.pid, "test")
            assert result.success
            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_dry_run_does_not_kill(self, responder):
        proc = subprocess.Popen(["sleep", "300"])
        try:
            result = responder.kill_process(proc.pid)
            assert result.success and result.dry_run
            assert proc.poll() is None  # still alive
        finally:
            proc.kill()

    def test_protected_pids_refused(self, responder):
        assert not responder.kill_process(1).success
        assert not responder.kill_process(0).success
        assert not responder.kill_process(os.getpid()).success

    def test_ancestor_refused(self, responder):
        # Killing our own parent chain would take down the operator's shell,
        # IDE, or supervisor along with the "target". (Under init-as-parent
        # environments the protected-PID guard fires first — either refusal
        # is correct.)
        assert not responder.kill_process(os.getppid()).success
        detail = responder.log.load()[0]["detail"]
        assert "ancestor" in detail or "protected" in detail

    def test_gone_process_is_success(self, responder):
        result = responder.kill_process(2**22)  # almost certainly absent
        assert result.success
        assert "no longer exists" in result.detail


class TestQuarantine:
    def test_quarantine_and_restore(self, responder, tmp_path):
        src = tmp_path / "evil.sh"
        src.write_text("#!/bin/sh\nrm -rf /\n")
        os.chmod(src, 0o755)
        result = responder.quarantine_file(src)
        assert result.success and result.dry_run
        assert src.exists()  # dry-run didn't touch it

        r2 = Responder(log_path=responder.log.path,
                       quarantine_dir=responder.quarantine_dir, dry_run=False)
        result = r2.quarantine_file(src)
        assert result.success
        assert not src.exists()
        manifest = r2.manifest()
        assert len(manifest) == 1
        qpath = r2.quarantine_dir / manifest[0]["id"]
        assert stat.S_IMODE(os.stat(qpath).st_mode) == 0o000
        assert stat.S_IMODE(os.stat(r2.quarantine_dir / "manifest.jsonl").st_mode) == 0o600

        restored = r2.restore_file(manifest[0]["id"][:8])
        assert restored.success
        assert src.read_text() == "#!/bin/sh\nrm -rf /\n"
        assert stat.S_IMODE(os.stat(src).st_mode) == 0o755

    def test_refuses_system_paths(self, responder):
        assert not responder.quarantine_file("/etc/passwd").success
        assert not responder.quarantine_file("/usr/bin/python3").success

    def test_refuses_symlink(self, responder, tmp_path):
        target = tmp_path / "real"
        target.write_text("x")
        link = tmp_path / "link"
        link.symlink_to(target)
        assert not responder.quarantine_file(link).success

    def test_refuses_missing(self, responder, tmp_path):
        assert not responder.quarantine_file(tmp_path / "nope").success


class TestBlockIp:
    def test_dry_run_block(self, responder):
        result = responder.block_ip("203.0.113.66", "C2")
        assert result.success and result.dry_run
        assert "iptables" in result.detail

    def test_refuses_bad_addresses(self, responder):
        for bad in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "not-an-ip", "::1"):
            assert not responder.block_ip(bad).success, bad

    def test_no_iptables_graceful(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        r = Responder(log_path=tmp_path / "r.jsonl", quarantine_dir=tmp_path / "v",
                      dry_run=False)
        result = r.block_ip("203.0.113.66")
        assert not result.success
        assert "iptables not found" in result.detail


class TestRuleResponse:
    def test_valid_responses_parse(self):
        for resp in VALID_RESPONSES:
            rule = Rule.from_dict({
                "id": "T", "name": "t", "severity": "low", "event_type": "process",
                "conditions": [{"field": "pid", "op": "exists"}], "response": resp})
            assert rule.response == resp

    def test_invalid_response_rejected(self):
        with pytest.raises(ValueError):
            Rule.from_dict({
                "id": "T", "name": "t", "severity": "low", "event_type": "process",
                "conditions": [], "response": "rm_rf_slash"})


class TestHandleAlert:
    def _engine(self):
        rule = Rule.from_dict({
            "id": "T-KILL", "name": "t", "severity": "critical",
            "event_type": "process",
            "conditions": [{"field": "exe_deleted", "op": "eq", "value": True}],
            "response": "kill_process"})
        return DetectionEngine([rule])

    def test_dispatches_declared_response(self, tmp_path):
        r = Responder(log_path=tmp_path / "r.jsonl", quarantine_dir=tmp_path / "v",
                      dry_run=True)
        engine = self._engine()
        alert = engine.evaluate({"type": "process", "pid": 4242, "exe_deleted": True})[0]
        results = r.handle_alert(alert, {rule.id: rule for rule in engine.rules})
        assert len(results) == 1 and results[0].dry_run

    def test_no_response_no_action(self, tmp_path):
        r = Responder(log_path=tmp_path / "r.jsonl", quarantine_dir=tmp_path / "v")
        engine = DetectionEngine([Rule.from_dict({
            "id": "T-NOACT", "name": "t", "severity": "low", "event_type": "process",
            "conditions": [{"field": "pid", "op": "exists"}]})])
        alert = engine.evaluate({"type": "process", "pid": 1})[0]
        assert r.handle_alert(alert, {"T-NOACT": engine.rules[0]}) == []

    def test_once_per_target(self, tmp_path):
        r = Responder(log_path=tmp_path / "r.jsonl", quarantine_dir=tmp_path / "v",
                      dry_run=True)
        engine = self._engine()
        rules = {rule.id: rule for rule in engine.rules}
        a1 = engine.evaluate({"type": "process", "pid": 4242, "exe_deleted": True})[0]
        a2 = engine.evaluate({"type": "process", "pid": 4242, "exe_deleted": True})[0]
        assert len(r.handle_alert(a1, rules)) == 1
        assert r.handle_alert(a2, rules) == []  # same target: suppressed

    def test_agent_wires_responder(self, tmp_path):
        sink = AlertSink(tmp_path / "alerts.jsonl", echo=False)
        r = Responder(log_path=tmp_path / "r.jsonl", quarantine_dir=tmp_path / "v",
                      dry_run=True)
        agent = Agent(self._engine(), sink, responder=r)
        alerts = agent._dispatch(agent.engine.evaluate(
            {"type": "process", "pid": 4242, "exe_deleted": True}))
        assert len(alerts) == 1
        log = r.log.load()
        assert len(log) == 1 and log[0]["action"] == "kill_process"


class TestResponseLog:
    def test_log_perms_and_order(self, tmp_path):
        r = Responder(log_path=tmp_path / "sub" / "r.jsonl",
                      quarantine_dir=tmp_path / "v", dry_run=True)
        r.kill_process(2**22)
        r.block_ip("203.0.113.9")
        path = tmp_path / "sub" / "r.jsonl"
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        events = r.log.load()
        assert events[0]["action"] == "block_ip"   # newest first
        assert events[1]["action"] == "kill_process"
