"""Audit log: who did what, when, from where — appended as JSONL, 0600 perms."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

DEFAULT_AUDIT_PATH = Path.home() / ".aegis" / "audit.jsonl"


def log_event(path: Path | str, user: str, action: str, detail: str = "",
              ip: str = "") -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": user[:64],
        "action": action[:64],
        "detail": detail[:300],
        "ip": ip[:45],  # fits an IPv6 literal
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_events(path: Path | str, limit: int = 200) -> List[dict]:
    path = Path(path)
    if not path.exists():
        return []
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [json.loads(l) for l in lines[-limit:]][::-1]  # newest first
