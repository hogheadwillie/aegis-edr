"""Network monitor: snapshots live connections into detection events."""

from __future__ import annotations

from typing import Iterator

import psutil

SHELL_LIKE = {"sh", "bash", "dash", "zsh", "ash", "nc", "ncat", "netcat", "socat",
              "python", "python3", "perl", "ruby", "php", "lua", "powershell", "pwsh"}


def iter_network_events() -> Iterator[dict]:
    """Yield one event per established outbound connection and per listener."""
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return

    proc_names = {}
    for proc in psutil.process_iter(["pid", "name"]):
        proc_names[proc.info["pid"]] = proc.info.get("name") or ""

    for conn in conns:
        name = proc_names.get(conn.pid, "") if conn.pid else ""
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            yield {
                "type": "network",
                "direction": "outbound",
                "process": name,
                "pid": conn.pid,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "local_port": conn.laddr.port if conn.laddr else None,
                "is_shell": name.lower() in SHELL_LIKE,
            }
        elif conn.status == psutil.CONN_LISTEN and conn.laddr:
            yield {
                "type": "network",
                "direction": "listen",
                "process": name,
                "pid": conn.pid,
                "remote_ip": "",
                "remote_port": None,
                "local_port": conn.laddr.port,
                "is_shell": name.lower() in SHELL_LIKE,
            }
