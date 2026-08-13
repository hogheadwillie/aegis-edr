"""Active response: containment actions for confirmed detections.

Three actions, each mapped from a detection rule's optional "response" key:

- kill_process(pid)  — SIGTERM, then SIGKILL, with guard rails
- quarantine_file(path) — move the file into a 0700 vault, strip all
  permissions, record a manifest so it can be restored
- block_ip(ip) — host firewall DROP rules (iptables) for a C2 address

Safety posture — these are defensive containment actions on your own hosts:
- dry_run is the DEFAULT: nothing is executed unless the caller opts in
  (CLI: --execute; auto-response: --auto-respond --execute).
- Hard guards refuse dangerous targets: PID 0/1, ourselves, our own process
  ancestors, init/sshd and other system daemons; system directories for
  quarantine; loopback, multicast and unspecified addresses for firewall rules.
- Every action — executed, dry-run, or refused — is appended to the
  response log (JSONL, 0600) for audit.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import psutil

DEFAULT_RESPONSE_LOG = Path.home() / ".aegis" / "response.jsonl"
DEFAULT_QUARANTINE_DIR = Path.home() / ".aegis" / "quarantine"
DEFAULT_BLOCKED_PATH = Path.home() / ".aegis" / "blocked_ips.json"

VALID_RESPONSES = ("kill_process", "quarantine_file", "block_ip")

# Never signal these: killing them bricks the host or locks you out.
PROTECTED_PIDS = {0, 1}
PROTECTED_PROCESS_NAMES = {
    "systemd", "init", "sshd", "dbus-daemon", "rsyslogd", "cron", "crond",
    "NetworkManager", "systemd-journald", "systemd-logind",
}

# Never quarantine from these trees — removing a file there breaks the OS.
PROTECTED_PATH_PREFIXES = (
    "/bin", "/sbin", "/lib", "/lib64", "/usr", "/boot", "/etc",
)

MAX_QUARANTINE_BYTES = 512 * 1024 * 1024  # refuse absurdly large files


def _ancestor_pids() -> set:
    """PIDs of every ancestor of this process — never kill your own tree."""
    ancestors = set()
    try:
        proc = psutil.Process(os.getpid())
        while proc.ppid() and proc.ppid() not in (0, 1):
            ancestors.add(proc.ppid())
            proc = psutil.Process(proc.ppid())
    except psutil.Error:
        pass
    return ancestors


@dataclass
class ResponseResult:
    action: str
    target: str
    success: bool
    detail: str
    dry_run: bool
    ts: str = ""

    def to_dict(self) -> dict:
        return {"ts": self.ts, "action": self.action, "target": self.target,
                "success": self.success, "dry_run": self.dry_run,
                "detail": self.detail[:300]}


class ResponseLog:
    """Append-only JSONL record of every response action (0600)."""

    def __init__(self, path: Path | str = DEFAULT_RESPONSE_LOG) -> None:
        self.path = Path(path)

    def record(self, result: ResponseResult) -> None:
        result.ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")

    def load(self, limit: int = 200) -> List[dict]:
        if not self.path.exists():
            return []
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines()
                 if l.strip()]
        return [json.loads(l) for l in lines[-limit:]][::-1]


class Responder:
    """Executes (or simulates) containment actions with guard rails."""

    def __init__(self, log_path: Path | str = DEFAULT_RESPONSE_LOG,
                 quarantine_dir: Path | str = DEFAULT_QUARANTINE_DIR,
                 blocked_path: Path | str = DEFAULT_BLOCKED_PATH,
                 dry_run: bool = True) -> None:
        self.log = ResponseLog(log_path)
        self.quarantine_dir = Path(quarantine_dir)
        self.blocked_path = Path(blocked_path)
        self.dry_run = dry_run
        self._done: set = set()  # (action, target) once per process lifetime

    # -- kill a malicious process ---------------------------------------------

    def kill_process(self, pid: int, reason: str = "") -> ResponseResult:
        result = ResponseResult("kill_process", str(pid), False, "", self.dry_run)
        try:
            pid = int(pid)
            if pid in PROTECTED_PIDS:
                raise ValueError(f"refusing to kill PID {pid} (protected)")
            if pid == os.getpid():
                raise ValueError("refusing to kill the Aegis agent itself")
            if pid in _ancestor_pids():
                raise ValueError(f"refusing to kill an ancestor of the Aegis process (pid {pid})")
            proc = psutil.Process(pid)
            name = proc.name() or ""
            if name in PROTECTED_PROCESS_NAMES:
                raise ValueError(f"refusing to kill protected daemon {name!r}")
            cmdline = " ".join(proc.cmdline())[:200]
            if self.dry_run:
                result.success = True
                result.detail = f"dry-run: would SIGTERM/SIGKILL {name} ({cmdline}) {reason}"
            else:
                proc.terminate()
                if self._wait_gone(proc, timeout=3):
                    pass
                else:
                    proc.kill()
                    self._wait_gone(proc, timeout=3)
                result.success = True
                result.detail = f"killed {name} pid={pid} ({cmdline}) {reason}"
        except psutil.NoSuchProcess:
            result.success = True  # already gone — containment goal met
            result.detail = f"pid {pid} no longer exists {reason}"
        except (ValueError, psutil.AccessDenied) as exc:
            result.detail = f"refused: {exc}"
        self.log.record(result)
        return result

    @staticmethod
    def _wait_gone(proc: psutil.Process, timeout: float) -> bool:
        """Poll until the process exits — os.waitpid only works on children."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                return True
            time.sleep(0.05)
        return not proc.is_running()

    # -- quarantine a malicious file ------------------------------------------

    def quarantine_file(self, path: Path | str, reason: str = "") -> ResponseResult:
        target = str(path)
        result = ResponseResult("quarantine_file", target, False, "", self.dry_run)
        try:
            src = Path(path)
            if src.is_symlink():
                raise ValueError("refusing to quarantine a symlink")
            src = src.resolve(strict=True)
            if not src.is_file():
                raise ValueError("not a regular file")
            if src.parts and src.parts[0] == "/" and len(src.parts) > 1 and \
                    any(str(src).startswith(p + "/") or str(src) == p
                        for p in PROTECTED_PATH_PREFIXES):
                raise ValueError(f"{src} is under a protected system directory")
            size = src.stat().st_size
            if size > MAX_QUARANTINE_BYTES:
                raise ValueError(f"file too large to quarantine ({size} bytes)")
            digest = hashlib.sha256(src.read_bytes()).hexdigest()
            mode = src.stat().st_mode & 0o777
            qpath = self.quarantine_dir / digest
            if self.dry_run:
                result.success = True
                result.detail = (f"dry-run: would move {src} -> {qpath} "
                                 f"(sha256 {digest[:16]}…) {reason}")
            else:
                self.quarantine_dir.mkdir(parents=True, exist_ok=True)
                os.chmod(self.quarantine_dir, 0o700)
                shutil.move(str(src), str(qpath))
                os.chmod(qpath, 0o000)  # inert: no read, no write, no exec
                self._manifest_append({
                    "id": digest, "original_path": str(src), "sha256": digest,
                    "size": size, "mode": oct(mode),
                    "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                })
                result.success = True
                result.detail = (f"quarantined {src} as {digest[:16]}… "
                                 f"(mode 000 in vault) {reason}")
        except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
            result.detail = f"refused: {exc}"
        self.log.record(result)
        return result

    def restore_file(self, quarantine_id: str) -> ResponseResult:
        result = ResponseResult("restore_file", quarantine_id, False, "", self.dry_run)
        entry = next((e for e in self._manifest_load()
                      if e["id"].startswith(quarantine_id)), None)
        try:
            if entry is None:
                raise ValueError(f"no quarantined file matching {quarantine_id!r}")
            qpath = self.quarantine_dir / entry["id"]
            dest = Path(entry["original_path"])
            if dest.exists():
                raise ValueError(f"destination {dest} already exists")
            if self.dry_run:
                result.success = True
                result.detail = f"dry-run: would restore {qpath} -> {dest}"
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(qpath, 0o600)
                shutil.move(str(qpath), str(dest))
                os.chmod(dest, int(entry["mode"], 8))
                result.success = True
                result.detail = f"restored to {dest}"
        except (ValueError, PermissionError, OSError) as exc:
            result.detail = f"refused: {exc}"
        self.log.record(result)
        return result

    # -- firewall-block a C2 address --------------------------------------------

    def block_ip(self, ip: str, reason: str = "") -> ResponseResult:
        result = ResponseResult("block_ip", ip, False, "", self.dry_run)
        try:
            addr = ipaddress.ip_address(ip.strip())
            if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
                raise ValueError(f"refusing to block {addr} (loopback/multicast/unspecified)")
            iptables = shutil.which("iptables")
            commands = [
                [iptables or "iptables", "-A", "OUTPUT", "-d", str(addr), "-j", "DROP"],
                [iptables or "iptables", "-A", "INPUT", "-s", str(addr), "-j", "DROP"],
            ]
            if self.dry_run:
                result.success = True
                result.detail = ("dry-run: would run " +
                                 " ; ".join(" ".join(c) for c in commands) + f" {reason}")
            else:
                if iptables is None:
                    raise ValueError("iptables not found on this host")
                for cmd in commands:
                    subprocess.run(cmd, check=True, capture_output=True, timeout=10)
                self._blocked_add(str(addr))
                result.success = True
                result.detail = f"blocked {addr} via iptables {reason}"
        except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            result.detail = f"refused: {exc}"
        self.log.record(result)
        return result

    def unblock_ip(self, ip: str) -> ResponseResult:
        result = ResponseResult("unblock_ip", ip, False, "", self.dry_run)
        try:
            addr = ipaddress.ip_address(ip.strip())
            iptables = shutil.which("iptables")
            commands = [
                [iptables or "iptables", "-D", "OUTPUT", "-d", str(addr), "-j", "DROP"],
                [iptables or "iptables", "-D", "INPUT", "-s", str(addr), "-j", "DROP"],
            ]
            if self.dry_run:
                result.success = True
                result.detail = "dry-run: would run " + " ; ".join(" ".join(c) for c in commands)
            else:
                if iptables is None:
                    raise ValueError("iptables not found on this host")
                for cmd in commands:
                    subprocess.run(cmd, check=True, capture_output=True, timeout=10)
                self._blocked_remove(str(addr))
                result.success = True
                result.detail = f"unblocked {addr}"
        except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            result.detail = f"refused: {exc}"
        self.log.record(result)
        return result

    def blocked_ips(self) -> List[str]:
        if not self.blocked_path.exists():
            return []
        return sorted(json.loads(self.blocked_path.read_text(encoding="utf-8")))

    # -- rule-driven dispatch --------------------------------------------------

    def handle_alert(self, alert, rules_by_id: Dict[str, object]) -> List[ResponseResult]:
        """Run the response declared by the alert's rule, if any.

        Each (action, target) fires at most once per Responder lifetime so a
        watch loop doesn't hammer the same containment repeatedly.
        """
        rule = rules_by_id.get(alert.rule_id)
        action = getattr(rule, "response", None) if rule else None
        if not action:
            return []
        event = alert.event or {}
        reason = f"[{alert.rule_id} {alert.severity}]"
        if action == "kill_process":
            target = event.get("pid")
        elif action == "quarantine_file":
            target = event.get("path")
        elif action == "block_ip":
            target = event.get("remote_ip")
        else:
            return []
        if target in (None, ""):
            result = ResponseResult(action, "?", False,
                                    f"event has no target field for {action} {reason}",
                                    self.dry_run)
            self.log.record(result)
            return [result]
        key = (action, str(target))
        if key in self._done:
            return []
        self._done.add(key)
        if action == "kill_process":
            return [self.kill_process(int(target), reason)]
        if action == "quarantine_file":
            return [self.quarantine_file(str(target), reason)]
        return [self.block_ip(str(target), reason)]

    # -- quarantine manifest & blocked-ip state ---------------------------------

    def _manifest_path(self) -> Path:
        return self.quarantine_dir / "manifest.jsonl"

    def _manifest_append(self, entry: dict) -> None:
        path = self._manifest_path()
        if not path.exists():
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _manifest_load(self) -> List[dict]:
        path = self._manifest_path()
        if not path.exists():
            return []
        return [json.loads(l) for l in
                path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def manifest(self) -> List[dict]:
        return self._manifest_load()

    def _blocked_add(self, ip: str) -> None:
        blocked = set(self.blocked_ips()) | {ip}
        self.blocked_path.parent.mkdir(parents=True, exist_ok=True)
        self.blocked_path.write_text(json.dumps(sorted(blocked)), encoding="utf-8")
        os.chmod(self.blocked_path, 0o600)

    def _blocked_remove(self, ip: str) -> None:
        blocked = set(self.blocked_ips()) - {ip}
        self.blocked_path.write_text(json.dumps(sorted(blocked)), encoding="utf-8")
