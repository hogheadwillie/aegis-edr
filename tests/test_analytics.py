"""Tests for the analytics layer: taxonomy, ledger, correlation, baselining."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from aegis.alerts import Alert, AlertSink, load_alerts
from aegis.analytics import baseline as bl
from aegis.analytics.correlate import correlate, save_incidents
from aegis.analytics.ledger import GENESIS, SealedLedger, recover, verify_pair
from aegis.analytics.taxonomy import classify_alert, tactic_summary, tactics_for


def make_alert(rule_id="PROC-002", severity="critical", event=None, mitre=None,
               timestamp=None) -> Alert:
    return Alert(rule_id=rule_id, name="test alert", severity=severity,
                 description="d", event_type="process",
                 event=event if event is not None else {"type": "process", "pid": 4242},
                 mitre=mitre or ["T1055"], host="testhost",
                 timestamp=timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"))


# -- taxonomy ---------------------------------------------------------------

class TestTaxonomy:
    def test_tactics_kill_chain_ordered(self):
        tactics = tactics_for(["T1071", "T1059"])
        assert tactics == ["Execution", "Command and Control"]

    def test_unknown_technique_ignored(self):
        assert tactics_for(["T9999"]) == []

    def test_classify_alert(self):
        assert classify_alert(make_alert(mitre=["T1003"])) == ["Credential Access"]

    def test_summary_counts(self):
        alerts = [make_alert(mitre=["T1059"]), make_alert(mitre=["T1059", "T1071"])]
        summary = tactic_summary(alerts)
        assert summary["Execution"] == 2
        assert summary["Command and Control"] == 1


# -- ledger -----------------------------------------------------------------

class TestSealedLedger:
    def test_append_verify_roundtrip(self, tmp_path):
        ledger = SealedLedger(tmp_path / "seal.jsonl")
        ledger.append({"a": 1})
        ledger.append({"b": 2})
        ok, detail = SealedLedger.verify(tmp_path / "seal.jsonl")
        assert ok, detail
        assert "2 entries" in detail

    def test_chain_links(self, tmp_path):
        ledger = SealedLedger(tmp_path / "seal.jsonl")
        d1 = ledger.append({"a": 1})
        d2 = ledger.append({"a": 2})
        lines = [json.loads(l) for l in (tmp_path / "seal.jsonl").read_text().splitlines()]
        assert lines[0]["prev"] == GENESIS
        assert lines[1]["prev"] == d1 and lines[1]["digest"] == d2

    def test_resume_after_reopen(self, tmp_path):
        SealedLedger(tmp_path / "seal.jsonl").append({"n": 1})
        ledger = SealedLedger(tmp_path / "seal.jsonl")  # reopen
        ledger.append({"n": 2})
        ok, _ = SealedLedger.verify(tmp_path / "seal.jsonl")
        assert ok

    def test_tamper_detected(self, tmp_path):
        ledger = SealedLedger(tmp_path / "seal.jsonl")
        ledger.append({"clean": True})
        ledger.append({"clean": True})
        path = tmp_path / "seal.jsonl"
        lines = path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["record"]["clean"] = False  # attacker rewrites history
        lines[0] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")
        ok, detail = SealedLedger.verify(path)
        assert not ok and "digest mismatch" in detail

    def test_deletion_detected(self, tmp_path):
        ledger = SealedLedger(tmp_path / "seal.jsonl")
        for i in range(3):
            ledger.append({"i": i})
        path = tmp_path / "seal.jsonl"
        path.write_text("\n".join(path.read_text().splitlines()[:2]) + "\n")
        ok, detail = verify_pair(_write_plain(tmp_path, [{"i": 0}, {"i": 1}, {"i": 2}]), path)
        assert not ok and "seal has 2" in detail

    def test_perms(self, tmp_path):
        seal = tmp_path / "d" / "seal.jsonl"
        SealedLedger(seal, replicas=[tmp_path / "d" / "r.jsonl"]).append({"x": 1})
        assert stat.S_IMODE(os.stat(seal).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(seal.parent).st_mode) == 0o700

    def test_replicas_mirrored_and_recover(self, tmp_path):
        rep = [tmp_path / "a.jsonl", tmp_path / "b.jsonl"]
        ledger = SealedLedger(tmp_path / "main.jsonl", replicas=rep)
        for i in range(3):
            ledger.append({"i": i})
        (tmp_path / "main.jsonl").unlink()  # lose the primary
        ok, detail = recover(tmp_path / "main.jsonl", rep)
        assert ok and "3 entries" in detail
        ok, _ = SealedLedger.verify(tmp_path / "main.jsonl")
        assert ok

    def test_recover_refuses_corrupt_replicas(self, tmp_path):
        bad = tmp_path / "bad.jsonl"
        bad.write_text('{"seq": 9, "prev": "x", "digest": "y", "record": {}}\n')
        ok, detail = recover(tmp_path / "out.jsonl", [bad])
        assert not ok and "no intact replica" in detail

    def test_sink_sealing_matches_plain_log(self, tmp_path):
        sink = AlertSink(tmp_path / "alerts.jsonl", echo=False, seal_dir=tmp_path / "sealed")
        sink.emit(make_alert())
        sink.emit(make_alert(event={"type": "network", "remote_ip": "10.0.0.9"}))
        ok, detail = verify_pair(tmp_path / "alerts.jsonl", tmp_path / "sealed" / "alerts.seal.jsonl")
        assert ok, detail
        # plain log stays readable by the rest of the app
        assert len(load_alerts(tmp_path / "alerts.jsonl")) == 2

    def test_pair_detects_plain_log_edit(self, tmp_path):
        sink = AlertSink(tmp_path / "alerts.jsonl", echo=False, seal_dir=tmp_path / "sealed")
        sink.emit(make_alert())
        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        record = json.loads(lines[0])
        record["severity"] = "low"  # attacker downgrades the alert in the plain log
        (tmp_path / "alerts.jsonl").write_text(json.dumps(record) + "\n")
        ok, detail = verify_pair(tmp_path / "alerts.jsonl", tmp_path / "sealed" / "alerts.seal.jsonl")
        assert not ok and "diverges" in detail


def _write_plain(tmp_path, records):
    path = tmp_path / "plain.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


# -- correlation --------------------------------------------------------------

class TestCorrelation:
    def test_shared_pid_merges_cross_source(self):
        a1 = make_alert(rule_id="PROC-002", event={"type": "process", "pid": 4242})
        a2 = make_alert(rule_id="NET-001", severity="medium",
                        event={"type": "network", "pid": 4242, "remote_ip": "203.0.113.9"},
                        mitre=["T1071"])
        incidents = correlate([a1, a2])
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.severity == "critical"          # max of members
        assert set(inc.rule_ids) == {"PROC-002", "NET-001"}
        assert inc.entities["remote_ip"] == ["203.0.113.9"]
        assert "Command and Control" in inc.tactics

    def test_no_shared_entity_stays_separate(self):
        a1 = make_alert(event={"type": "process", "pid": 1})
        a2 = make_alert(event={"type": "process", "pid": 2})
        assert len(correlate([a1, a2])) == 2

    def test_window_splits_same_entity(self):
        now = datetime.now(timezone.utc)
        a1 = make_alert(timestamp=(now - timedelta(hours=1)).isoformat(timespec="seconds"))
        a2 = make_alert(timestamp=now.isoformat(timespec="seconds"))
        assert len(correlate([a1, a2], window_seconds=300)) == 2
        assert len(correlate([a1, a2], window_seconds=7200)) == 1

    def test_transitive_chain(self):
        # pid 7 -> shared by a1,a2 ; ip shared by a2,a3 -> all one incident
        a1 = make_alert(event={"type": "process", "pid": 7})
        a2 = make_alert(event={"type": "network", "pid": 7, "remote_ip": "198.51.100.2"})
        a3 = make_alert(rule_id="NET-002", severity="medium",
                        event={"type": "network", "remote_ip": "198.51.100.2"})
        incidents = correlate([a1, a2, a3])
        assert len(incidents) == 1 and len(incidents[0].alert_ids) == 3

    def test_severity_sort_and_save_perms(self, tmp_path):
        a1 = make_alert(severity="medium", event={"type": "process", "pid": 1})
        a2 = make_alert(severity="critical", event={"type": "process", "pid": 2})
        incidents = correlate([a1, a2])
        assert incidents[0].severity == "critical"
        path = tmp_path / "inc" / "incidents.jsonl"
        save_incidents(incidents, path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_empty(self):
        assert correlate([]) == []


# -- baseline -----------------------------------------------------------------

def _sample(**overrides):
    base = {m: 10.0 for m in bl.METRICS}
    base.update(overrides)
    return base


class TestBaseline:
    def test_learn_and_score_normal(self):
        samples = [_sample(process_count=p, listen_count=2) for p in (98, 100, 102)]
        baseline = bl.Baseline.learn(samples)
        z, _ = baseline.score(_sample(process_count=101, listen_count=2))
        assert z < 4.0

    def test_spike_scores_high(self):
        samples = [_sample(process_count=p, listen_count=2) for p in (98, 100, 102)]
        baseline = bl.Baseline.learn(samples)
        z, zscores = baseline.score(_sample(process_count=300, listen_count=40))
        assert z >= 8.0
        assert zscores["listen_count"] > zscores["process_count"] - 1000  # sanity

    def test_constant_metric_still_flags(self):
        # deleted_exe_count pinned at 0 in baseline: 0 -> 1 must register
        samples = [_sample(deleted_exe_count=0) for _ in range(4)]
        baseline = bl.Baseline.learn(samples)
        z, zscores = baseline.score(_sample(deleted_exe_count=3))
        assert zscores["deleted_exe_count"] >= 4.0

    def test_needs_min_samples(self):
        with pytest.raises(ValueError):
            bl.Baseline.learn([_sample()])

    def test_save_load_perms(self, tmp_path):
        baseline = bl.Baseline.learn([_sample(process_count=p) for p in (98, 100, 102)])
        path = tmp_path / "b" / "baseline.json"
        bl.save_baseline(baseline, path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        loaded = bl.load_baseline(path)
        assert loaded.stats["process_count"]["mean"] == pytest.approx(100.0)

    def test_load_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            bl.load_baseline(tmp_path / "nope.json")

    def test_anomaly_alert_fields(self):
        alert = bl.anomaly_alert(9.5, {"listen_count": 9.5, "process_count": 1.0}, host="h")
        assert alert.rule_id == "ANOM-001"
        assert alert.severity == "critical"
        assert alert.event_type == "anomaly"
        assert alert.event["max_z"] == 9.5

    def test_severity_ladder(self):
        assert bl.severity_for(4.5) == "medium"
        assert bl.severity_for(6.5) == "high"
        assert bl.severity_for(9.0) == "critical"

    def test_real_sensors_sample(self):
        # smoke-test against the live sensors: all metrics present and numeric
        sample = bl.sample_metrics()
        for metric in bl.METRICS:
            assert isinstance(sample[metric], float)
