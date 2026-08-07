"""Aegis EDR command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional

from .agent import Agent, hostname
from .alerts import AlertSink, SEVERITY_RANK, load_alerts
from .detection.engine import DetectionEngine, load_iocs, load_rules
from .monitors import fim

AEGIS_HOME = Path.home() / ".aegis"
RULES_PATH = Path(__file__).resolve().parent / "rules" / "default_rules.json"


def _ioc_path() -> Path:
    return AEGIS_HOME / "iocs.json"


def _baseline_path(watch_dir: Path) -> Path:
    key = hashlib.sha256(str(watch_dir.resolve()).encode()).hexdigest()[:12]
    return AEGIS_HOME / "fim" / f"{key}.json"


def _build_agent(args) -> Agent:
    rules = load_rules(getattr(args, "rules", None) or RULES_PATH)
    iocs = load_iocs(_ioc_path())
    engine = DetectionEngine(rules, iocs, host=hostname())
    sink = AlertSink(AEGIS_HOME / "alerts.jsonl", echo=not getattr(args, "quiet", False),
                     min_severity=getattr(args, "min_severity", "low"))
    return Agent(engine, sink)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis EDR — host-based detection: process, network, and file-integrity monitoring.",
    )
    parser.add_argument("--rules", type=Path, help="custom rules file or directory")
    parser.add_argument("--quiet", action="store_true", help="log alerts without console echo")
    parser.add_argument("--min-severity", choices=list(SEVERITY_RANK), default="low")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="one-shot scan: processes + network connections")

    p_watch = sub.add_parser("watch", help="continuous monitoring loop")
    p_watch.add_argument("--interval", type=float, default=5.0, help="seconds between polls")
    p_watch.add_argument("--cycles", type=int, help="stop after N polls (default: run until Ctrl-C)")

    p_fim = sub.add_parser("fim", help="file integrity monitoring")
    fim_sub = p_fim.add_subparsers(dest="fim_command", required=True)
    p_base = fim_sub.add_parser("baseline", help="record a baseline for a directory")
    p_base.add_argument("directory", type=Path)
    p_check = fim_sub.add_parser("check", help="diff a directory against its baseline")
    p_check.add_argument("directory", type=Path)

    p_ioc = sub.add_parser("ioc", help="manage the IOC feed")
    ioc_sub = p_ioc.add_subparsers(dest="ioc_command", required=True)
    p_ioc_add = ioc_sub.add_parser("add", help="add an indicator")
    p_ioc_add.add_argument("--ip", help="malicious IP address")
    p_ioc_add.add_argument("--domain", help="malicious domain")
    p_ioc_add.add_argument("--sha256", help="malicious file hash")
    ioc_sub.add_parser("list", help="show the feed")

    p_report = sub.add_parser("report", help="summarize the alert log")
    p_report.add_argument("--severity", choices=list(SEVERITY_RANK),
                          help="only show alerts at or above this severity")

    p_serve = sub.add_parser("serve", help="run the web dashboard (localhost by default)")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--allow-remote", action="store_true",
                         help="permit binding to non-loopback addresses (use with TLS + a proxy)")
    p_serve.add_argument("--secure-cookies", action="store_true",
                         help="mark session cookies Secure (set when serving over HTTPS)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "ioc":
        return _cmd_ioc(args)

    agent = _build_agent(args)

    if args.command == "scan":
        alerts = agent.full_scan()
        print(f"\nScan complete: {len(alerts)} alert(s). "
              f"Log: {AEGIS_HOME / 'alerts.jsonl'}")
        return 2 if any(SEVERITY_RANK[a.severity] >= SEVERITY_RANK["high"] for a in alerts) else 0

    if args.command == "watch":
        print(f"Watching (poll every {args.interval}s, Ctrl-C to stop)...")
        agent.watch(interval=args.interval, cycles=args.cycles)
        return 0

    if args.command == "fim":
        directory: Path = args.directory
        if args.fim_command == "baseline":
            baseline = fim.build_baseline(directory)
            path = _baseline_path(directory)
            fim.save_baseline(baseline, path)
            print(f"Baselined {len(baseline)} file(s) under {directory} -> {path}")
            return 0
        try:
            alerts = agent.scan_files(directory, _baseline_path(directory))
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"FIM check complete: {len(alerts)} alert(s).")
        return 2 if alerts else 0

    if args.command == "report":
        return _cmd_report(args)

    if args.command == "serve":
        from .web.server import serve
        serve(host=args.host, port=args.port, allow_remote=args.allow_remote,
              rules_path=getattr(args, "rules", None),
              secure_cookies=args.secure_cookies)
        return 0

    return 0


def _cmd_ioc(args) -> int:
    path = _ioc_path()
    if args.ioc_command == "list":
        iocs = load_iocs(path)
        for category, values in sorted(iocs.items()):
            print(f"{category}: {len(values)}")
            for v in sorted(values):
                print(f"  {v}")
        return 0
    iocs = load_iocs(path)
    added = False
    for category in ("ip", "domain", "sha256"):
        value = getattr(args, category, None)
        if value:
            iocs.setdefault(category, set()).add(value.strip())
            print(f"Added {category} IOC: {value}")
            added = True
    if not added:
        print("error: provide --ip, --domain, or --sha256", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({k: sorted(v) for k, v in iocs.items()}, indent=2),
                    encoding="utf-8")
    return 0


def _cmd_report(args) -> int:
    alerts = load_alerts(AEGIS_HOME / "alerts.jsonl")
    if args.severity:
        cutoff = SEVERITY_RANK[args.severity]
        alerts = [a for a in alerts if SEVERITY_RANK[a.severity] >= cutoff]
    if not alerts:
        print("No alerts recorded.")
        return 0
    by_sev = Counter(a.severity for a in alerts)
    by_rule = Counter(f"{a.rule_id} {a.name}" for a in alerts)
    print(f"Total alerts: {len(alerts)}  (host: {alerts[0].host or 'unknown'})\n")
    print("By severity:")
    for sev in ("critical", "high", "medium", "low"):
        if by_sev.get(sev):
            print(f"  {sev:8} {by_sev[sev]}")
    print("\nTop detections:")
    for rule, count in by_rule.most_common(10):
        print(f"  {count:4}  {rule}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
