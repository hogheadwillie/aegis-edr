"""Unit tests for the Aegis detection engine, alerts, FIM, and agent."""

import json

import pytest

from aegis.agent import Agent
from aegis.alerts import Alert, AlertSink, load_alerts
from aegis.detection.engine import (Condition, DetectionEngine, Rule,
                                    load_iocs, load_rules)
from aegis.monitors import fim

RULES_PATH = __import__("pathlib").Path(__file__).resolve().parents[1] / "aegis" / "rules" / "default_rules.json"


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine(load_rules(RULES_PATH), iocs={"ip": {"203.0.113.66"}},
                           host="test-host")


class TestConditions:
    def test_all_operators(self):
        e = {"a": "Hello World", "n": 5, "ip": "1.2.3.4"}
        assert Condition("a", "eq", "Hello World").matches(e, {})
        assert Condition("a", "ne", "x").matches(e, {})
        assert Condition("a", "contains", "hello").matches(e, {})
        assert Condition("a", "contains_any", ["zzz", "world"]).matches(e, {})
        assert Condition("a", "startswith", "hell").matches(e, {})
        assert Condition("a", "endswith", "WORLD").matches(e, {})
        assert Condition("a", "regex", r"lo\s+Wo").matches(e, {})
        assert Condition("n", "gt", 4).matches(e, {})
        assert Condition("n", "lt", 6).matches(e, {})
        assert Condition("n", "in", [1, 5]).matches(e, {})
        assert Condition("missing", "exists").matches(e, {}) is False
        assert Condition("ip", "in_ioc", "ip").matches(e, {"ip": {"1.2.3.4"}})

    def test_dotted_field(self):
        e = {"proc": {"name": "bash"}}
        assert Condition("proc.name", "eq", "bash").matches(e, {})
        assert Condition("proc.missing", "eq", "x").matches(e, {}) is False

    def test_unknown_operator_rejected(self):
        with pytest.raises(ValueError):
            Condition("a", "frobnicate", 1).matches({"a": 1}, {})


class TestRuleMatching:
    def test_event_type_gating(self, engine):
        event = {"type": "network", "exe_dir": "/tmp"}  # right fields, wrong type
        assert engine.evaluate(event) == []

    def test_temp_execution_fires(self, engine):
        event = {"type": "process", "exe_dir": "/tmp", "exe": "/tmp/x", "cmdline": "/tmp/x"}
        hits = engine.evaluate(event)
        assert {h.rule_id for h in hits} == {"PROC-001"}
        assert hits[0].severity == "high"
        assert "T1059" in hits[0].mitre

    def test_deleted_binary_is_critical(self, engine):
        event = {"type": "process", "exe": "/tmp/x (deleted)", "exe_deleted": True,
                 "exe_dir": "/tmp", "cmdline": "/tmp/x"}
        hits = {h.rule_id: h for h in engine.evaluate(event)}
        assert hits["PROC-002"].severity == "critical"

    def test_encoded_command_any_logic(self, engine):
        event = {"type": "process", "exe_dir": "/usr/bin", "cmdline": "echo aGVsbG8= | base64 -d | sh"}
        assert "PROC-003" in {h.rule_id for h in engine.evaluate(event)}

    def test_clean_process_no_alerts(self, engine):
        event = {"type": "process", "exe_dir": "/usr/bin", "exe": "/usr/bin/python3",
                 "exe_deleted": False, "cmdline": "python3 manage.py runserver"}
        assert engine.evaluate(event) == []

    def test_ioc_ip_fires(self, engine):
        event = {"type": "network", "direction": "outbound", "remote_ip": "203.0.113.66",
                 "remote_port": 443, "is_shell": False}
        hits = {h.rule_id for h in engine.evaluate(event)}
        assert "NET-001" in hits
        assert "NET-002" not in hits

    def test_reverse_shell_pattern(self, engine):
        event = {"type": "network", "direction": "outbound", "remote_ip": "198.51.100.9",
                 "remote_port": 4444, "is_shell": True}
        hits = {h.rule_id for h in engine.evaluate(event)}
        assert {"NET-002", "NET-003"} <= hits

    def test_fim_sensitive_file(self, engine):
        event = {"type": "file_change", "change": "modified", "path": "/home/u/.ssh/authorized_keys"}
        hits = {h.rule_id for h in engine.evaluate(event)}
        assert hits == {"FIM-001"}


class TestAlerts:
    def test_severity_validation(self):
        with pytest.raises(ValueError):
            Alert(rule_id="X", name="x", severity="bogus", description="",
                  event_type="process", event={})

    def test_sink_roundtrip_and_filtering(self, tmp_path, capsys):
        sink = AlertSink(tmp_path / "alerts.jsonl", echo=True, min_severity="high")
        low = Alert(rule_id="L", name="low", severity="low", description="",
                    event_type="process", event={"pid": 1})
        high = Alert(rule_id="H", name="high", severity="high", description="",
                     event_type="process", event={"pid": 2})
        sink.emit(low)
        sink.emit(high)
        out = capsys.readouterr().out
        assert "high" in out and "low\n" not in out.split("H")[0]
        loaded = load_alerts(tmp_path / "alerts.jsonl")
        assert [a.rule_id for a in loaded] == ["L", "H"]


class TestFIM:
    def test_baseline_diff_created_modified_deleted(self, tmp_path):
        root = tmp_path / "watch"
        root.mkdir()
        (root / "keep.txt").write_text("v1")
        (root / "gone.txt").write_text("bye")
        baseline = fim.build_baseline(root)

        (root / "keep.txt").write_text("v2")          # modified
        (root / "gone.txt").unlink()                  # deleted
        (root / "new.sh").write_text("#!/bin/sh\n")   # created

        changes = {(e["path"], e["change"]) for e in fim.diff_baseline(baseline, root)}
        assert (str(root / "keep.txt"), "modified") in changes
        assert (str(root / "gone.txt"), "deleted") in changes
        assert (str(root / "new.sh"), "created") in changes
        assert len(changes) == 3

    def test_missing_baseline_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            fim.load_baseline(tmp_path / "nope.json")


class TestAgent:
    def test_dedup_suppresses_repeat_alerts(self, tmp_path, engine):
        sink = AlertSink(tmp_path / "a.jsonl", echo=False)
        agent = Agent(engine, sink)
        event = {"type": "process", "pid": 4242, "exe_dir": "/tmp", "exe": "/tmp/x",
                 "cmdline": "/tmp/x"}
        first = agent._dispatch(engine.evaluate(event))
        second = agent._dispatch(engine.evaluate(event))
        assert len(first) == 1 and second == []
