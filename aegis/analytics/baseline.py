"""Behavioral baselining: learn the host's normal signal profile, alert on deviation.

The host is sampled repeatedly (process and network sensors) to build a
statistical profile of "normal". Thereafter each sample is scored against
that profile with per-metric z-scores; a strong deviation — the system no
longer "resonating" with its baseline — raises an anomaly alert through the
normal alert pipeline.
"""

from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean, pstdev
from typing import Dict, Iterable, List, Optional, Tuple

from ..alerts import Alert
from ..monitors import network, process

METRICS = (
    "process_count",
    "deleted_exe_count",
    "established_count",
    "listen_count",
    "distinct_remote_ips",
    "distinct_remote_ports",
)

DEFAULT_THRESHOLD = 4.0   # max z-score that still counts as "normal"
MIN_SAMPLES = 3

ANOMALY_RULE_ID = "ANOM-001"
ANOMALY_NAME = "Behavioral baseline deviation"


def sample_metrics() -> Dict[str, float]:
    """Take one sensor snapshot and reduce it to baseline metrics."""
    procs = list(process.iter_process_events())
    conns = list(network.iter_network_events())
    established = [c for c in conns if c.get("direction") == "outbound"]
    listening = [c for c in conns if c.get("direction") == "listen"]
    return {
        "process_count": float(len(procs)),
        "deleted_exe_count": float(sum(1 for p in procs if p.get("exe_deleted"))),
        "established_count": float(len(established)),
        "listen_count": float(len(listening)),
        "distinct_remote_ips": float(len({c.get("remote_ip") for c in established
                                          if c.get("remote_ip")})),
        "distinct_remote_ports": float(len({c.get("remote_port") for c in established
                                            if c.get("remote_port")})),
    }


class Baseline:
    """Mean/stdev profile per metric, with z-score scoring."""

    def __init__(self, stats: Optional[Dict[str, Dict[str, float]]] = None) -> None:
        self.stats = stats or {}

    @classmethod
    def learn(cls, samples: Iterable[Dict[str, float]]) -> "Baseline":
        samples = list(samples)
        if len(samples) < MIN_SAMPLES:
            raise ValueError(f"need at least {MIN_SAMPLES} samples to learn a baseline")
        stats = {}
        for metric in METRICS:
            values = []
            for s in samples:
                v = s.get(metric, 0.0)
                if not isinstance(v, (int, float)) or not math.isfinite(v):
                    raise ValueError(f"non-numeric sample value for {metric}: {v!r}")
                values.append(float(v))
            mean = fmean(values)
            stdev = pstdev(values)
            # Floor the spread: a metric pinned at one value must still be
            # able to flag change (e.g. deleted_exe_count 0 -> 1).
            stats[metric] = {"mean": mean, "stdev": max(stdev, 0.5), "n": len(values)}
        return cls(stats)

    def score(self, sample: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        """Return (max_z, per-metric z-scores) for a sample.

        Only known metrics are scored; hostile extra keys in the sample are
        ignored. Non-finite inputs are treated as maximally anomalous rather
        than crashing.
        """
        zscores = {}
        for metric, s in self.stats.items():
            if metric not in METRICS:
                continue
            value = sample.get(metric, 0.0)
            if not isinstance(value, (int, float)) or not math.isfinite(value):
                zscores[metric] = float("inf")
                continue
            zscores[metric] = abs(value - s["mean"]) / s["stdev"]
        return (max(zscores.values(), default=0.0), zscores)

    def to_dict(self) -> dict:
        return {"learned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "stats": self.stats}

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        if not isinstance(data, dict):
            raise ValueError("baseline file must be a JSON object")
        stats = data.get("stats", {})
        if not isinstance(stats, dict):
            raise ValueError("baseline 'stats' must be an object")
        clean: Dict[str, Dict[str, float]] = {}
        for metric, s in stats.items():
            if metric not in METRICS:
                continue  # drop unknown/hostile metric names
            if not isinstance(s, dict):
                raise ValueError(f"baseline stat {metric!r} must be an object")
            mean, stdev = s.get("mean"), s.get("stdev")
            if not isinstance(mean, (int, float)) or not math.isfinite(mean):
                raise ValueError(f"baseline stat {metric!r}: bad mean {mean!r}")
            if not isinstance(stdev, (int, float)) or not math.isfinite(stdev) or stdev <= 0:
                raise ValueError(f"baseline stat {metric!r}: bad stdev {stdev!r}")
            clean[metric] = {"mean": float(mean), "stdev": float(stdev),
                             "n": int(s.get("n", 0))}
        return cls(stats=clean)


def save_baseline(baseline: Baseline, path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(baseline.to_dict(), fh, indent=2)


def load_baseline(path: Path | str) -> Baseline:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"no baseline at {path} — run 'aegis baseline learn' first")
    return Baseline.from_dict(json.loads(path.read_text(encoding="utf-8")))


def severity_for(z: float) -> str:
    if z >= 8.0:
        return "critical"
    if z >= 6.0:
        return "high"
    return "medium"


def anomaly_alert(z: float, zscores: Dict[str, float], host: str = "") -> Alert:
    """Build the alert emitted when a sample breaks the baseline."""
    worst = sorted(zscores.items(), key=lambda kv: kv[1], reverse=True)[:3]
    detail = ", ".join(f"{m} z={v:.1f}" for m, v in worst)
    return Alert(
        rule_id=ANOMALY_RULE_ID, name=ANOMALY_NAME, severity=severity_for(z),
        description=f"Host behavior diverged from its learned baseline ({detail}). "
                    "No rule matched — this is statistical anomaly detection.",
        event_type="anomaly",
        event={"type": "anomaly", "max_z": round(z, 2),
               "zscores": {k: round(v, 2) for k, v in zscores.items()}},
        mitre=[], host=host,
    )
