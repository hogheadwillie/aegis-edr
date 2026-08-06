"""File Integrity Monitor (FIM): hash baselines and change detection."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterator, List

_CHUNK = 1 << 20  # 1 MiB


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_baseline(root: Path | str) -> Dict[str, str]:
    """Map every regular file under root to its SHA-256. Symlinks are not followed."""
    root = Path(root)
    baseline: Dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            try:
                baseline[str(path)] = _hash_file(path)
            except (OSError, PermissionError):
                continue
    return baseline


def diff_baseline(old: Dict[str, str], root: Path | str) -> List[dict]:
    """Compare a stored baseline to the current state; return change events."""
    new = build_baseline(root)
    events: List[dict] = []
    for path, digest in new.items():
        if path not in old:
            events.append({"type": "file_change", "change": "created",
                           "path": path, "sha256": digest})
        elif old[path] != digest:
            events.append({"type": "file_change", "change": "modified",
                           "path": path, "sha256": digest})
    for path in old:
        if path not in new:
            events.append({"type": "file_change", "change": "deleted",
                           "path": path, "sha256": None})
    return events


def save_baseline(baseline: Dict[str, str], path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    try:
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_baseline(path: Path | str) -> Dict[str, str]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"no baseline at {path}; run 'aegis fim baseline' first")
    return json.loads(path.read_text(encoding="utf-8"))
