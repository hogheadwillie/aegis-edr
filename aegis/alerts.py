"""Alert model and dispatch pipeline."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Alert:
    """A single detection alert."""

    rule_id: str
    name: str
    severity: str
    description: str
    event_type: str
    event: dict
    mitre: List[str] = field(default_factory=list)
    host: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")

    def dedup_key(self) -> str:
        """Stable identity used to suppress duplicate alerts in watch mode."""
        subject = self.event.get("pid") or self.event.get("path") or self.event.get("remote_ip") or ""
        return f"{self.rule_id}:{subject}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})

    def one_line(self) -> str:
        subject = (
            self.event.get("cmdline")
            or self.event.get("path")
            or f"{self.event.get('process', '?')} -> {self.event.get('remote_ip', '?')}:{self.event.get('remote_port', '?')}"
        )
        mitre = f" [{' '.join(self.mitre)}]" if self.mitre else ""
        return (f"{self.severity.upper():8} {self.rule_id:8} {self.name}: "
                f"{str(subject)[:80]}{mitre}")


class AlertSink:
    """Appends alerts to a JSONL log and echoes them to the console.

    When `seal_dir` is given, every alert is additionally sealed into a
    hash-chained, replicated ledger (analytics.ledger) for tamper evidence.
    """

    def __init__(self, log_path: Path | str, echo: bool = True, min_severity: str = "low",
                 seal_dir: Path | str | None = None) -> None:
        self.log_path = Path(log_path)
        self.echo = echo
        self.min_rank = SEVERITY_RANK[min_severity]
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Alert logs may contain sensitive host data — restrict access.
        try:
            os.chmod(self.log_path.parent, 0o700)
        except OSError:
            pass
        self._seal = None
        if seal_dir is not None:
            from .analytics.ledger import SealedLedger
            seal_dir = Path(seal_dir)
            self._seal = SealedLedger(
                seal_dir / "alerts.seal.jsonl",
                replicas=[seal_dir / "replica-a.seal.jsonl", seal_dir / "replica-b.seal.jsonl"])

    def emit(self, alert: Alert) -> None:
        if not self.log_path.exists():
            fd = os.open(str(self.log_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        record = alert.to_dict()
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        if self._seal is not None:
            self._seal.append(record)
        if self.echo and SEVERITY_RANK[alert.severity] >= self.min_rank:
            print(f"[{alert.timestamp}] {alert.one_line()}")


def load_alerts(log_path: Path | str) -> List[Alert]:
    """Load the alert log, skipping corrupt/tampered lines instead of dying.

    A single bad line must never make the entire log unreadable — that's both
    a robustness property and a security one (an attacker who can append one
    bad byte shouldn't be able to blind the reporting path).
    """
    path = Path(log_path)
    if not path.exists():
        return []
    alerts = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                alerts.append(Alert.from_dict(record))
        except (json.JSONDecodeError, ValueError, TypeError):
            continue  # drop the corrupt line, keep the rest
    return alerts
