"""Incident correlation: fuse cross-source alerts into one incident graph.

A single intrusion surfaces as separate process, network, and file alerts.
This engine merges alerts that share an entity (PID, remote IP, or file
path) within a time window into a single incident — the security analog of
treating spatially separated observations as one correlated event.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from ..alerts import SEVERITY_RANK
from .taxonomy import tactics_for

DEFAULT_WINDOW_SECONDS = 300  # 5 minutes


@dataclass
class Incident:
    title: str
    severity: str
    first_seen: str
    last_seen: str
    alert_ids: List[str]
    rule_ids: List[str]
    entities: Dict[str, List[str]]      # {"pid": [...], "remote_ip": [...], "path": [...]}
    tactics: List[str]
    host: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        return asdict(self)

    def one_line(self) -> str:
        ents = []
        for kind in ("pid", "remote_ip", "path"):
            if self.entities.get(kind):
                ents.append(f"{kind}={','.join(self.entities[kind][:3])}")
        return (f"{self.severity.upper():8} {self.id}  {self.title}  "
                f"[{len(self.alert_ids)} alerts; {'; '.join(ents)}]")


def _parse_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _entities_of(alert) -> List[Tuple[str, str]]:
    out = []
    for kind in ("pid", "remote_ip", "path"):
        value = alert.event.get(kind)
        if value not in (None, ""):
            out.append((kind, str(value)))
    return out


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def correlate(alerts: Iterable, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> List[Incident]:
    """Group alerts into incidents via shared entities within a time window."""
    alerts = sorted(alerts, key=lambda a: _parse_ts(a.timestamp))
    n = len(alerts)
    if n == 0:
        return []
    uf = _UnionFind(n)
    times = [_parse_ts(a.timestamp) for a in alerts]

    by_entity: Dict[Tuple[str, str], List[int]] = {}
    for i, alert in enumerate(alerts):
        for key in _entities_of(alert):
            for j in by_entity.get(key, []):
                if abs(times[i] - times[j]) <= window_seconds:
                    uf.union(i, j)
            by_entity.setdefault(key, []).append(i)

    clusters: Dict[int, List[int]] = {}
    for i in range(n):
        clusters.setdefault(uf.find(i), []).append(i)

    incidents = []
    for members in clusters.values():
        group = [alerts[i] for i in members]
        top = max(group, key=lambda a: SEVERITY_RANK[a.severity])
        ents: Dict[str, Set[str]] = {}
        for a in group:
            for kind, value in _entities_of(a):
                ents.setdefault(kind, set()).add(value)
        incidents.append(Incident(
            title=top.name,
            severity=top.severity,
            first_seen=min(a.timestamp for a in group),
            last_seen=max(a.timestamp for a in group),
            alert_ids=[a.id for a in group],
            rule_ids=sorted({a.rule_id for a in group}),
            entities={k: sorted(v) for k, v in ents.items()},
            tactics=tactics_for(t for a in group for t in a.mitre),
            host=top.host,
        ))
    incidents.sort(key=lambda inc: (-SEVERITY_RANK[inc.severity], inc.first_seen))
    return incidents


def save_incidents(incidents: Iterable[Incident], path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for inc in incidents:
            fh.write(json.dumps(inc.to_dict(), ensure_ascii=False) + "\n")
