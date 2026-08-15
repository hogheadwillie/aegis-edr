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


def _seal_dir() -> Path:
    return AEGIS_HOME / "sealed"


def _seal_paths() -> tuple:
    d = _seal_dir()
    return d / "alerts.seal.jsonl", [d / "replica-a.seal.jsonl", d / "replica-b.seal.jsonl"]


def _build_agent(args) -> Agent:
    rules = load_rules(getattr(args, "rules", None) or RULES_PATH)
    iocs = load_iocs(_ioc_path())
    engine = DetectionEngine(rules, iocs, host=hostname())
    sink = AlertSink(AEGIS_HOME / "alerts.jsonl", echo=not getattr(args, "quiet", False),
                     min_severity=getattr(args, "min_severity", "low"), seal_dir=_seal_dir())
    responder = None
    if getattr(args, "auto_respond", False):
        from .response.actions import Responder
        responder = Responder(dry_run=not getattr(args, "execute", False))
    return Agent(engine, sink, responder=responder)


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

    for p in (sub.choices["scan"], p_watch):
        p.add_argument("--auto-respond", action="store_true",
                       help="run rule-declared containment on alerts (dry-run unless --execute)")
        p.add_argument("--execute", action="store_true",
                       help="actually perform containment actions (default: dry-run)")

    p_fim = sub.add_parser("fim", help="file integrity monitoring")
    fim_sub = p_fim.add_subparsers(dest="fim_command", required=True)
    p_base = fim_sub.add_parser("baseline", help="record a baseline for a directory")
    p_base.add_argument("directory", type=Path)
    p_check = fim_sub.add_parser("check", help="diff a directory against its baseline")
    p_check.add_argument("directory", type=Path)
    p_check.add_argument("--auto-respond", action="store_true",
                         help="run rule-declared containment on alerts (dry-run unless --execute)")
    p_check.add_argument("--execute", action="store_true",
                         help="actually perform containment actions (default: dry-run)")

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

    p_user = sub.add_parser("user", help="manage dashboard accounts (Argon2id-hashed)")
    user_sub = p_user.add_subparsers(dest="user_command", required=True)
    p_uadd = user_sub.add_parser("add", help="create an account")
    p_uadd.add_argument("username")
    p_uadd.add_argument("--role", choices=["admin", "analyst"], default="analyst")
    p_uadd.add_argument("--password", help="omit to generate a random one")
    p_udel = user_sub.add_parser("remove", help="delete an account")
    p_udel.add_argument("username")
    p_upw = user_sub.add_parser("passwd", help="change a password")
    p_upw.add_argument("username")
    user_sub.add_parser("list", help="show accounts")

    p_token = sub.add_parser("token", help="manage the JSON API token")
    token_sub = p_token.add_subparsers(dest="token_command", required=True)
    token_sub.add_parser("show", help="print the current token")
    token_sub.add_parser("rotate", help="generate a new token, invalidating the old one")

    p_resp = sub.add_parser("respond", help="manual containment actions (dry-run by default)")
    p_resp.add_argument("--execute", action="store_true",
                        help="actually perform the action (default: dry-run)")
    resp_sub = p_resp.add_subparsers(dest="respond_command", required=True)
    p_rkill = resp_sub.add_parser("kill", help="terminate a process (SIGTERM, then SIGKILL)")
    p_rkill.add_argument("pid", type=int)
    p_rq = resp_sub.add_parser("quarantine", help="move a file into the quarantine vault")
    p_rq.add_argument("path", type=Path)
    p_rr = resp_sub.add_parser("restore", help="restore a quarantined file by id prefix")
    p_rr.add_argument("quarantine_id")
    p_rb = resp_sub.add_parser("block", help="firewall-block an IP (iptables DROP)")
    p_rb.add_argument("ip")
    p_ru = resp_sub.add_parser("unblock", help="remove firewall rules for an IP")
    p_ru.add_argument("ip")
    resp_sub.add_parser("blocked", help="list firewall-blocked IPs")
    resp_sub.add_parser("vault", help="list quarantined files")
    resp_sub.add_parser("log", help="show the response action log")

    p_inc = sub.add_parser("incidents", help="correlate alerts into cross-source incidents")
    p_inc.add_argument("--window", type=int, default=300,
                       help="correlation window in seconds (default 300)")

    p_al = sub.add_parser("alerts", help="tamper-evident alert ledger")
    al_sub = p_al.add_subparsers(dest="alerts_command", required=True)
    al_sub.add_parser("verify", help="verify the sealed ledger against the alert log")
    al_sub.add_parser("recover", help="rebuild a lost/corrupt seal from its replicas")

    p_bl = sub.add_parser("baseline", help="behavioral baseline anomaly detection")
    bl_sub = p_bl.add_subparsers(dest="baseline_command", required=True)
    p_bl_learn = bl_sub.add_parser("learn", help="sample the host and learn its normal profile")
    p_bl_learn.add_argument("--cycles", type=int, default=5, help="samples to take (default 5)")
    p_bl_learn.add_argument("--interval", type=float, default=2.0, help="seconds between samples")
    p_bl_check = bl_sub.add_parser("check", help="score the host against the baseline")
    p_bl_check.add_argument("--threshold", type=float, default=4.0,
                            help="z-score that counts as anomalous (default 4.0)")
    bl_sub.add_parser("show", help="print the learned baseline")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "ioc":
        return _cmd_ioc(args)

    if args.command == "respond":
        return _cmd_respond(args)

    if args.command == "incidents":
        return _cmd_incidents(args)

    if args.command == "alerts":
        return _cmd_alerts(args)

    if args.command == "baseline":
        return _cmd_baseline(args)

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

    if args.command == "user":
        return _cmd_user(args)

    if args.command == "token":
        return _cmd_token(args)

    return 0


def _cmd_respond(args) -> int:
    from .response.actions import Responder

    responder = Responder(dry_run=not args.execute)
    cmd = args.respond_command
    if cmd == "kill":
        result = responder.kill_process(args.pid)
    elif cmd == "quarantine":
        result = responder.quarantine_file(args.path)
    elif cmd == "restore":
        result = responder.restore_file(args.quarantine_id)
    elif cmd == "block":
        result = responder.block_ip(args.ip)
    elif cmd == "unblock":
        result = responder.unblock_ip(args.ip)
    elif cmd == "blocked":
        blocked = responder.blocked_ips()
        print("\n".join(blocked) if blocked else "No blocked IPs.")
        return 0
    elif cmd == "vault":
        for entry in responder.manifest():
            print(f"  {entry['id'][:16]}…  {entry['original_path']}  ({entry['size']} B)")
        if not responder.manifest():
            print("Quarantine vault is empty.")
        return 0
    else:  # log
        events = responder.log.load()
        if not events:
            print("No response actions recorded.")
        for e in events:
            mark = "OK " if e["success"] else "ERR"
            mode = "dry" if e["dry_run"] else "EXE"
            print(f"[{mark}|{mode}] {e['ts']} {e['action']:16} {e['target']:40} {e['detail']}")
        return 0
    print(("DRY-RUN " if result.dry_run else "") + result.detail)
    return 0 if result.success else 1


def _cmd_incidents(args) -> int:
    from .analytics.correlate import correlate, save_incidents

    alerts = load_alerts(AEGIS_HOME / "alerts.jsonl")
    if not alerts:
        print("No alerts recorded.")
        return 0
    incidents = correlate(alerts, window_seconds=args.window)
    path = AEGIS_HOME / "incidents.jsonl"
    save_incidents(incidents, path)
    print(f"{len(incidents)} incident(s) from {len(alerts)} alert(s) -> {path}\n")
    for inc in incidents:
        print(inc.one_line())
        if inc.tactics:
            print(f"           tactics: {', '.join(inc.tactics)}  rules: {', '.join(inc.rule_ids)}")
    return 2 if any(i.severity == "critical" for i in incidents) else 0


def _cmd_alerts(args) -> int:
    from .analytics.ledger import recover, verify_pair

    seal, replicas = _seal_paths()
    if args.alerts_command == "verify":
        ok, detail = verify_pair(AEGIS_HOME / "alerts.jsonl", seal)
        print(("OK  " if ok else "FAIL ") + detail)
        return 0 if ok else 1
    ok, detail = recover(seal, replicas)
    print(("OK  " if ok else "FAIL ") + detail)
    return 0 if ok else 1


def _cmd_baseline(args) -> int:
    from .analytics import baseline as bl

    path = AEGIS_HOME / "baseline.json"
    if args.baseline_command == "learn":
        samples = []
        for i in range(max(args.cycles, bl.MIN_SAMPLES)):
            samples.append(bl.sample_metrics())
            if i < args.cycles - 1:
                import time
                time.sleep(args.interval)
        baseline = bl.Baseline.learn(samples)
        bl.save_baseline(baseline, path)
        print(f"Learned baseline from {len(samples)} sample(s) -> {path}")
        for metric in bl.METRICS:
            s = baseline.stats[metric]
            print(f"  {metric:22} mean={s['mean']:.1f}  stdev={s['stdev']:.2f}")
        return 0
    if args.baseline_command == "show":
        try:
            baseline = bl.load_baseline(path)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for metric in bl.METRICS:
            s = baseline.stats.get(metric)
            if s:
                print(f"  {metric:22} mean={s['mean']:.1f}  stdev={s['stdev']:.2f}  n={s['n']}")
        return 0
    # check
    try:
        baseline = bl.load_baseline(path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    sample = bl.sample_metrics()
    z, zscores = baseline.score(sample)
    if z >= args.threshold:
        alert = bl.anomaly_alert(z, zscores, host=hostname())
        AlertSink(AEGIS_HOME / "alerts.jsonl", echo=False, seal_dir=_seal_dir()).emit(alert)
        print(f"ANOMALY [{alert.severity.upper()}] max z={z:.1f} — logged to {AEGIS_HOME / 'alerts.jsonl'}")
        for metric, value in sorted(zscores.items(), key=lambda kv: kv[1], reverse=True)[:3]:
            print(f"  {metric:22} z={value:.1f}")
        return 2
    print(f"Host within baseline (max z={z:.1f} < {args.threshold}).")
    return 0


def _cmd_token(args) -> int:
    from .web.security import load_or_create_token

    path = AEGIS_HOME / "api_token"
    if args.token_command == "rotate":
        path.unlink(missing_ok=True)  # force regeneration below
        token = load_or_create_token(path)
        print(f"Rotated API token (old one is dead): {token}")
        print("Restart 'aegis serve' for the running dashboard to pick it up.")
    else:
        print(load_or_create_token(path))
    return 0


def _cmd_user(args) -> int:
    from .web.auth import UserStore, generate_password

    store = UserStore(AEGIS_HOME / "users.json")
    try:
        if args.user_command == "add":
            password = args.password or generate_password()
            store.add_user(args.username, password, args.role)
            print(f"Created {args.role} account: {args.username}")
            if not args.password:
                print(f"Generated password: {password}")
                print("(store it now — it is Argon2id-hashed and cannot be recovered)")
        elif args.user_command == "remove":
            store.remove_user(args.username)
            print(f"Removed account: {args.username}")
        elif args.user_command == "passwd":
            import getpass
            password = getpass.getpass("New password (min 12 chars): ")
            store.change_password(args.username, password)
            print(f"Password updated for: {args.username}")
        elif args.user_command == "list":
            users = store.list_users()
            if not users:
                print("No accounts — the console is in single-token mode. "
                      "Run 'aegis user add <name> --role admin' to switch to multi-user.")
            for u in users:
                print(f"  {u.username:20} {u.role}")
        return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


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
    from .analytics.taxonomy import tactic_summary
    tactics = tactic_summary(alerts)
    if tactics:
        print("\nBy ATT&CK tactic:")
        for tactic, count in tactics.most_common():
            print(f"  {count:4}  {tactic}")
    print("\nTop detections:")
    for rule, count in by_rule.most_common(10):
        print(f"  {count:4}  {rule}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
