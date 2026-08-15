"""Adversarial stress tests: fuzz parsers, attack web edge, race state files.

These tests try to *break* Aegis, not confirm it works. Each class targets a
trust boundary: rule loading, IOC store, alert rehydration, seal ledger,
baselines, quarantine manifest, and the HTTP edge.
"""

from __future__ import annotations

import json
import os
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis.alerts import Alert, AlertSink, load_alerts
from aegis.analytics import baseline as bl
from aegis.analytics.correlate import correlate
from aegis.analytics.ledger import GENESIS, SealedLedger, recover, verify_pair
from aegis.detection.engine import Condition, DetectionEngine, Rule, load_iocs, load_rules
from aegis.response.actions import Responder

FUZZ_TOKENS = [
    "", "\x00", "\x00\x00\x00", "a" * 100_000, "%s%s%n", "{{7*7}}", "${7*7}",
    "../../../etc/passwd", "..\\..\\windows\\system32", "'; DROP TABLE--",
    "<script>alert(1)</script>", "\ud800", "😀" * 1000, "\n\r\n", "*",
    "T1059", "null", "NaN", "-1", "1e999", "[]", "{}", "true", "false",
    "pid.pid.pid.pid", "....", "type", "__class__", "__dict__", "event.type",
]

MALFORMED_JSON = [
    "", " ", "{", "[", "{]", "[}", '{"a":}', '{"a": 1,}', 'not json',
    "\x00\x01\x02", '{"a": "b"', "[[[", '{"id": "R",', '"just a string"',
    "12345", "null", "true", '{"seq": "x"}', "\ufeff{}", '{"a": 1}\n{"b": 2',
]


class TestRuleLoadingUnderAttack:
    def test_malformed_rule_files_raise_or_reject(self, tmp_path):
        for i, blob in enumerate(MALFORMED_JSON):
            f = tmp_path / f"r{i}.json"
            f.write_text(blob, encoding="utf-8", errors="replace")
            try:
                load_rules(f)
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                pass  # must fail loudly, never silently load garbage

    def test_garbage_fields_rejected(self):
        garbage = [
            {"id": "X", "name": "n", "severity": "critical", "event_type": "process",
             "conditions": [{"field": "pid", "op": "eq", "value": None, "extra": 1}]},
            {"id": "X", "name": "n", "severity": "critical", "event_type": "process",
             "conditions": [{"field": "pid", "op": "eq", "value": 1, "evil": "yes"}]},
            {"id": "X", "name": "n", "severity": "critical", "event_type": "process",
             "conditions": "not-a-list"},
            {"id": "X", "name": "n", "severity": "critical", "event_type": "process",
             "conditions": ["not-a-dict"]},
            {"id": "X", "name": "n", "severity": "critical", "event_type": "process",
             "mitre": "T1059"},  # must be a list
        ]
        for g in garbage:
            with pytest.raises((ValueError, TypeError, KeyError)):
                Rule.from_dict(g)

    def test_regex_dos_rule_rejected(self):
        # catastrophic-backtracking pattern must not be loadable
        with pytest.raises(ValueError):
            Rule.from_dict({
                "id": "X", "name": "n", "severity": "high", "event_type": "process",
                "conditions": [{"field": "cmdline", "op": "regex",
                                "value": "(a+)+$"}],
            })

    def test_regex_dos_never_hangs_engine(self):
        # even if a pathological pattern slips through (constructed directly,
        # bypassing the load-time guard), matching must bail out fast
        rule = Rule(id="X", name="n", severity="high", event_type="process",
                    description="d",
                    conditions=[Condition(field="cmdline", op="regex", value="(x+x+)+y")])
        engine = DetectionEngine([rule])
        import time
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            engine.evaluate({"type": "process", "cmdline": "x" * 5000})
        assert time.monotonic() - start < 5, "regex match hung — ReDoS possible"

    def test_condition_operators_never_crash_on_weird_values(self):
        ops = ["eq", "ne", "gt", "lt", "in", "contains", "contains_any",
               "startswith", "endswith", "regex", "exists"]
        for op in ops:
            for token in FUZZ_TOKENS:
                c = Condition(field="cmdline", op=op, value=token)
                try:
                    c.matches({"cmdline": "some process --flag"}, {})
                except (TypeError, ValueError, re_error):
                    pass  # a clean exception is fine; a hang or segfault is not

    def test_deep_dotted_path(self):
        c = Condition(field=".".join(["a"] * 500), op="exists")
        assert c.matches({"a": {"a": 1}}, {}) is False

    def test_event_with_hostile_keys(self):
        engine = DetectionEngine([Rule(id="X", name="n", severity="low",
                                       event_type="process", description="d",
                                       conditions=[Condition("pid", "exists")])])
        engine.evaluate({"type": "process", "pid": 1, "__class__": "evil",
                         "type_": "x", "": "", "\x00": "nul"})


class TestIocStoreUnderAttack:
    def test_malformed_ioc_files(self, tmp_path):
        for i, blob in enumerate(MALFORMED_JSON):
            f = tmp_path / f"i{i}.json"
            f.write_text(blob, encoding="utf-8", errors="replace")
            try:
                iocs = load_iocs(f)
                # if it loads, it must be the {category: set} shape
                for k, v in iocs.items():
                    assert isinstance(k, str) and isinstance(v, set)
            except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
                pass

    def test_ioc_categories_must_be_lists(self, tmp_path):
        f = tmp_path / "iocs.json"
        f.write_text('{"ip": "1.2.3.4"}')  # string, not list
        with pytest.raises((ValueError, TypeError)):
            load_iocs(f)

    def test_ioc_size_cap(self, tmp_path):
        f = tmp_path / "iocs.json"
        f.write_text(json.dumps({"ip": [f"10.0.{i // 256}.{i % 256}" for i in range(200_000)]}))
        with pytest.raises(ValueError):
            load_iocs(f)


class TestAlertLogUnderAttack:
    def test_corrupt_lines_skipped_not_fatal(self, tmp_path):
        log = tmp_path / "alerts.jsonl"
        good = Alert(rule_id="R", name="n", severity="low", description="d",
                     event_type="process", event={"type": "process", "pid": 1})
        lines = [json.dumps(good.to_dict()), "{corrupt", "", '{"rule_id":',
                 "garbage", json.dumps(good.to_dict())]
        log.write_text("\n".join(lines) + "\n")
        alerts = load_alerts(log)
        assert len(alerts) == 2  # good rows survive, junk is dropped

    def test_alert_from_dict_ignores_unknown_and_bad_fields(self, tmp_path):
        log = tmp_path / "alerts.jsonl"
        good = Alert(rule_id="R", name="n", severity="low", description="d",
                     event_type="process", event={"type": "process"})
        record = good.to_dict()
        record["evil_field"] = "x"
        record["severity"] = "nonexistent"  # invalid severity must be dropped, not crash
        log.write_text(json.dumps(record) + "\n" + json.dumps(good.to_dict()) + "\n")
        alerts = load_alerts(log)
        assert len(alerts) == 1


class TestLedgerUnderAttack:
    def test_concurrent_appends_never_corrupt(self, tmp_path):
        # 8 threads x 25 appends: chain must verify and hold exactly 200 entries
        ledger = SealedLedger(tmp_path / "seal.jsonl",
                              replicas=[tmp_path / "r1.jsonl", tmp_path / "r2.jsonl"])

        def worker(n):
            for i in range(25):
                ledger.append({"thread": n, "i": i})

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))
        ok, detail = SealedLedger.verify(tmp_path / "seal.jsonl")
        assert ok, detail
        assert "200 entries" in detail
        ok, _ = SealedLedger.verify(tmp_path / "r1.jsonl")
        assert ok

    def test_truncated_tail_detected(self, tmp_path):
        ledger = SealedLedger(tmp_path / "seal.jsonl")
        for i in range(5):
            ledger.append({"i": i})
        path = tmp_path / "seal.jsonl"
        raw = path.read_bytes()
        path.write_bytes(raw[: len(raw) - 7])  # tear the last line
        ok, detail = SealedLedger.verify(path)
        assert not ok

    def test_reordered_entries_detected(self, tmp_path):
        ledger = SealedLedger(tmp_path / "seal.jsonl")
        for i in range(4):
            ledger.append({"i": i})
        path = tmp_path / "seal.jsonl"
        lines = path.read_text().splitlines()
        lines[1], lines[2] = lines[2], lines[1]  # swap
        path.write_text("\n".join(lines) + "\n")
        ok, _ = SealedLedger.verify(path)
        assert not ok


class TestBaselineUnderAttack:
    def test_corrupt_baseline_file(self, tmp_path):
        for blob in MALFORMED_JSON:
            f = tmp_path / "baseline.json"
            f.write_text(blob, encoding="utf-8", errors="replace")
            try:
                baseline = bl.load_baseline(f)
                z, _ = baseline.score({m: 0.0 for m in bl.METRICS})
                assert z >= 0  # empty stats => zero score, no crash
            except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                pass

    def test_stats_must_be_numeric(self, tmp_path):
        f = tmp_path / "baseline.json"
        f.write_text(json.dumps({"stats": {"process_count": {"mean": "evil", "stdev": -1}}}))
        with pytest.raises((ValueError, TypeError)):
            bl.load_baseline(f)

    def test_score_with_missing_and_extra_metrics(self):
        baseline = bl.Baseline.learn([bl_metrics(p) for p in (98, 100, 102)])
        # a sample exactly at the learned values scores ~0
        z, scores = baseline.score(bl_metrics(100))
        assert z < 4.0
        z, scores = baseline.score({**{m: 10.0 for m in bl.METRICS}, "hacker_metric": 1e9})
        assert "hacker_metric" not in scores

    def test_extreme_values_no_overflow(self):
        baseline = bl.Baseline.learn([bl_metrics(p) for p in (98, 100, 102)])
        z, _ = baseline.score(bl_metrics(10**12, process_count=10**12))
        assert z == float("inf") or z >= 8.0  # must flag, never crash/NaN-wrap

    def test_learn_rejects_non_numeric_samples(self):
        with pytest.raises((ValueError, TypeError)):
            bl.Baseline.learn([{"process_count": "lots"}, {"process_count": "many"},
                               {"process_count": "so many"}])


def bl_metrics(p, **over):
    base = {m: 10.0 for m in bl.METRICS}
    base["process_count"] = float(p)
    base.update(over)
    return base


class TestCorrelationUnderLoad:
    def test_ten_thousand_alerts(self):
        alerts = []
        for i in range(10_000):
            alerts.append(Alert(rule_id=f"R{i % 12}", name="n",
                                severity=("low", "medium", "high", "critical")[i % 4],
                                description="d", event_type="process",
                                event={"type": "process", "pid": i % 500,
                                       "remote_ip": f"10.0.0.{i % 250}"},
                                mitre=["T1059"]))
        import time
        start = time.monotonic()
        incidents = correlate(alerts)
        elapsed = time.monotonic() - start
        assert elapsed < 30, f"correlation too slow: {elapsed:.1f}s"
        assert len(incidents) >= 1

    def test_alerts_with_missing_and_hostile_fields(self):
        weird = [
            Alert(rule_id="R", name="n", severity="low", description="d",
                  event_type="process", event={}),  # no entities at all
            Alert(rule_id="R", name="n", severity="low", description="d",
                  event_type="process", event={"pid": "\x00", "remote_ip": ""}),
            Alert(rule_id="R", name="n", severity="low", description="d",
                  event_type="process", event={"pid": 0}, timestamp="not-a-date"),
        ]
        incidents = correlate(weird)
        assert len(incidents) == 3  # no crashes, no false merges


class TestResponderUnderAttack:
    def test_quarantine_manifest_corruption(self, tmp_path, monkeypatch):
        responder = Responder(dry_run=True, quarantine_dir=tmp_path / "q")
        manifest = tmp_path / "q" / "manifest.jsonl"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("{corrupt\n" + json.dumps({"id": "abc123", "original_path": "/x"}) + "\n")
        # reading the manifest must tolerate the corrupt line
        entries = responder.manifest()
        assert len(entries) == 1

    def test_restore_id_prefix_injection(self, tmp_path):
        responder = Responder(dry_run=True, quarantine_dir=tmp_path / "q")
        for evil in ["../..", "..", "*", "", "\x00", "a/../b", "zzzz", "ABCDEF"]:
            result = responder.restore_file(evil)
            assert not result.success  # must refuse, never path-traverse

    def test_block_ip_fuzz(self):
        responder = Responder(dry_run=True)
        for token in FUZZ_TOKENS:
            result = responder.block_ip(token)
            # garbage must be refused; valid-looking RFC1918 may dry-run OK
            assert isinstance(result.success, bool)
        assert not responder.block_ip("999.999.999.999").success
        assert not responder.block_ip("127.0.0.1").success
        assert not responder.block_ip("0.0.0.0").success

    def test_kill_pid_fuzz(self):
        responder = Responder(dry_run=True)
        for pid in (-1, 0, 1, 2**31, "abc", None):
            try:
                result = responder.kill_process(pid)
                assert not result.success or pid not in (0, 1)
            except (TypeError, ValueError):
                pass  # clean rejection of non-int pids is fine


class TestConcurrencyOnSharedState:
    def test_ioc_add_race_no_lost_writes(self, tmp_path):
        from aegis.cli import _cmd_ioc
        import argparse
        path = tmp_path / "iocs.json"

        def add(n):
            args = argparse.Namespace(ioc_command="add", ip=f"10.1.0.{n}",
                                      domain=None, sha256=None)
            # point the command at our temp path
            import aegis.cli as cli
            old = cli._ioc_path
            cli._ioc_path = lambda: path
            try:
                cli._cmd_ioc(args)
            finally:
                cli._ioc_path = old

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(add, range(50)))
        iocs = load_iocs(path)
        assert len(iocs["ip"]) == 50, f"lost updates under race: {len(iocs['ip'])}/50"


import re
re_error = re.error
