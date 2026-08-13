"""Tests for active response: kill, quarantine, firewall block, dispatch."""

import json
import os
import subprocess
import time

import pytest

from aegis.alerts import Alert
from aegis.detection.engine import DetectionEngine, Rule
from aegis.response.actions import Responder, ResponseLog


@pytest.fixture()
def responder(tmp_path):
    return Responder(log_path=tmp_path / "response.jsonl",
                     quarantine_dir=tmp_path / "vault",
                     blocked_path=tmp_path / "blocked.json",
                     dry_run=False)


@pytest.fixture()
def dry_responder(tmp_path):
    return Responder(log_path=tmp_path / "response.jsonl",
                     quarantine_dir=tmp_path / "vault",
                     blocked_path=tmp_path / "blocked.json",
                     dry_run=True)


def _spawn():
    return subprocess.Popen(["sleep", "300"])


class TestKillProcess:
    def test_kill_real_process(self, responder):
        proc = _spawn()
        result = responder.kill_process(proc.pid, "[TEST]")
        assert result.success
        proc.wait(timeout=5)
        assert proc.poll() is not None  # actually dead

    def test_dry_run_leaves_process_alive(self, dry_responder):
        proc = _spawn()
        try:
            result = dry_responder.kill_process(proc.pid)
            assert result.success and result.dry_run
            assert proc.poll() is None  # untouched
        finally:
            proc.kill()

    def test_protected_pids_refused(self, responder):
        assert not responder.kill_process(1).success
        assert not responder.kill_process(0).success
        assert not responder.kill_process(os.getpid()).success

    def test_ancestor_refused(self, responder):
        # Killing our own parent chain would take down the operator's shell,
        # IDE, or supervisor along with the "target".
        assert not responder.kill_process(os.getppid()).success
        assert "ancestor" in responder.log.load()[0]["detail"]

    def test_gone_process_is_success(self, responder):
        result = responder.kill_process(2**22)  # almost certainly absent
        assert result.success
        assert "no longer exists" in result.detail


class TestQuarantine:
    def test_quarantine_and_restore(self, responder, tmp_path):
        target = tmp_path / "evil.sh"
        target.write_text("#!/bin/sh\necho pwned\n")
        os.chmod(target, 0o755)

        result = responder.quarantine_file(target)
        assert result.success
        assert not target.exists()
        entry = responder.manifest()[0]
        qpath = tmp_path / "vault" / entry["id"]
        assert qpath.exists()
        assert oct(os.stat(qpath).st_mode & 0o777) == "0o0"  # inert
        assert oct(os.stat(tmp_path / "vault" / "manifest.jsonl").st_mode & 0o777) == "0o600"

        restored = responder.restore_file(entry["id"][:8])
        assert restored.success
        assert target.read_text() == "#!/bin/sh\necho pwned\n"
        assert oct(os.stat(target).st_mode & 0o777) == "0o755"  # original mode

    def test_dry_run_keeps_file(self, dry_responder, tmp_path):
        target = tmp_path / "evil.sh"
        target.write_text("x")
        result = dry_responder.quarantine_file(target)
        assert result.success
        assert target.exists()

    def test_system_path_refused(self, responder):
        assert not responder.quarantine_file("/etc/passwd").success
        assert not responder.quarantine_file("/usr/bin/python3").success

    def test_symlink_refused(self, responder, tmp_path):
        real = tmp_path / "real.txt"
        real.write_text("x")
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        assert not responder.quarantine_file(link).success
        assert real.exists()

    def test_missing_file_refused(self, responder, tmp_path):
        assert not responder.quarantine_file(tmp_path / "nope.bin").success

    def test_restore_unknown_id_refused(self, responder):
        assert not responder.restore_file("deadbeef").success


class TestBlockIp:
    def test_dry_run_returns_commands(self, dry_responder):
        result = dry_responder.block_ip("203.0.113.66")
        assert result.success
        assert "iptables" in result.detail and "DROP" in result.detail

    def test_invalid_ip_refused(self, responder):
        assert not responder.block_ip("999.1.2.3").success
        assert not responder.block_ip("not-an-ip").success

    def test_loopback_and_multicast_refused(self, responder):
        assert not responder.block_ip("127.0.0.1").success
        assert not responder.block_ip("224.0.0.1").success
        assert not responder.block_ip("0.0.0.0").success

    def test_real_block_requires_iptables(self, responder, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda name: None)
        result = responder.block_ip("203.0.113.66")
        assert not result.success
        assert "iptables not found" in result.detail


class TestRuleResponseParsing:
    def test_valid_response_accepted(self):
        rule = Rule.from_dict({
            "id": "T-1", "name": "t", "severity": "high", "event_type": "process",
            "response": "kill_process",
            "conditions": [{"field": "pid", "op": "exists"}]})
        assert rule.response == "kill_process"

    def test_invalid_response_rejected(self):
        with pytest.raises(ValueError):
            Rule.from_dict({
                "id": "T-2", "name": "t", "severity": "high", "event_type": "process",
                "response": "rm_rf_slash",
                "conditions": [{"field": "pid", "op": "exists"}]})

    def test_default_rules_carry_responses(self):
        from aegis.cli import RULES_PATH
        from aegis.detection.engine import load_rules
        rules = {r.id: r for r in load_rules(RULES_PATH)}
        assert rules["PROC-002"].response == "kill_process"
        assert rules["NET-001"].response == "block_ip"
        assert rules["NET-004"].response == "kill_process"
        assert rules["FIM-003"].response == "quarantine_file"


class TestHandleAlert:
    def _rule(self, rid, response):
        return Rule(id=rid, name="t", severity="critical", event_type="process",
                    description="", response=response)

    def test_dispatches_kill_for_matching_rule(self, dry_responder):
        proc = _spawn()
        try:
            alert = Alert(rule_id="R-K", name="t", severity="critical",
                          description="", event_type="process",
                          event={"pid": proc.pid})
            results = dry_responder.handle_alert(alert, {"R-K": self._rule("R-K", "kill_process")})
            assert len(results) == 1
            assert results[0].action == "kill_process"
            assert results[0].success and proc.poll() is None  # dry-run
        finally:
            proc.kill()

    def test_no_response_means_no_action(self, dry_responder):
        alert = Alert(rule_id="R-0", name="t", severity="low", description="",
                      event_type="process", event={"pid": 123})
        assert dry_responder.handle_alert(alert, {"R-0": self._rule("R-0", None)}) == []

    def test_each_target_contained_once(self, dry_responder):
        alert = Alert(rule_id="R-K", name="t", severity="critical", description="",
                      event_type="process", event={"pid": 424242})
        rules = {"R-K": self._rule("R-K", "kill_process")}
        assert len(dry_responder.handle_alert(alert, rules)) == 1
        assert dry_responder.handle_alert(alert, rules) == []  # deduped

    def test_agent_wires_responder(self, tmp_path):
        from aegis.agent import Agent
        from aegis.alerts import AlertSink
        rule = Rule(id="R-K", name="t", severity="critical", event_type="process",
                    description="", response="kill_process",
                    conditions=[__import__("aegis.detection.engine", fromlist=["Condition"])
                                .Condition(field="pid", op="gt", value=0)])
        engine = DetectionEngine([rule])
        resp = Responder(log_path=tmp_path / "r.jsonl",
                         quarantine_dir=tmp_path / "v",
                         blocked_path=tmp_path / "b.json",
                         dry_run=True)
        agent = Agent(engine, AlertSink(tmp_path / "alerts.jsonl", echo=False),
                      responder=resp)
        alerts = agent._dispatch(engine.evaluate({"type": "process", "pid": 999}))
        assert len(alerts) == 1
        entries = ResponseLog(tmp_path / "r.jsonl").load()
        assert entries[0]["action"] == "kill_process"
        assert entries[0]["dry_run"] is True


class TestResponseLog:
    def test_log_written_with_perms(self, tmp_path):
        resp = Responder(log_path=tmp_path / "response.jsonl",
                         quarantine_dir=tmp_path / "v",
                         blocked_path=tmp_path / "b.json",
                         dry_run=True)
        resp.block_ip("203.0.113.66")
        log = tmp_path / "response.jsonl"
        assert oct(os.stat(log).st_mode & 0o777) == "0o600"
        entries = ResponseLog(log).load()
        assert entries[0]["action"] == "block_ip"
        assert entries[0]["target"] == "203.0.113.66"
