"""Process monitor: enumerates running processes into detection events."""

from __future__ import annotations

import os
from typing import Iterator

import psutil

_ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]


def _raw_exe(proc) -> str:
    """Executable path, preserving the ' (deleted)' marker.

    psutil strips the kernel's ' (deleted)' suffix, so on Linux we read the
    /proc/<pid>/exe symlink directly and fall back to psutil elsewhere.
    """
    pid = proc.info.get("pid")
    if pid and os.path.isdir("/proc"):
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            pass
    return proc.info.get("exe") or ""


def iter_process_events() -> Iterator[dict]:
    """Yield one event dict per live process. Access-denied entries are skipped."""
    parents = {}
    for proc in psutil.process_iter(["pid", "name"]):
        parents[proc.info["pid"]] = proc.info.get("name") or ""

    for proc in psutil.process_iter(_ATTRS):
        info = proc.info
        cmdline_list = info.get("cmdline") or []
        raw_exe = _raw_exe(proc)
        exe = raw_exe.removesuffix(" (deleted)")
        yield {
            "type": "process",
            "pid": info.get("pid"),
            "ppid": info.get("ppid"),
            "name": info.get("name") or "",
            "exe": exe,
            "exe_dir": os.path.dirname(exe) if exe else "",
            "exe_deleted": raw_exe.endswith(" (deleted)"),  # fileless / memfd execution
            "cmdline": " ".join(cmdline_list),
            "username": info.get("username") or "",
            "parent_name": parents.get(info.get("ppid") or -1, ""),
        }
