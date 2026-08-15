"""Tamper-evident, replicated alert ledger.

Every alert is additionally appended to a hash-chained seal log: each entry
binds its sequence number, the previous entry's digest, and the canonical
record, so editing, deleting, or reordering history breaks the chain. The
seal is mirrored to replica files so the ledger survives loss of any single
copy ("every fragment preserves the whole").

Honest limitation: this detects and recovers from tampering by processes
that cannot rewrite *all* copies consistently; a root-level attacker who
rewrites every replica can still forge history. Real forward integrity
requires shipping seals off-host (see README).
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import List, Optional, Tuple

GENESIS = "0" * 64


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _digest(seq: int, prev: str, record: dict) -> str:
    return hashlib.sha256(f"{seq}:{prev}:{_canonical(record)}".encode()).hexdigest()


class SealedLedger:
    """Append-only hash-chained JSONL log with synchronous replicas.

    Appends are serialized by a process-wide lock *and* an fcntl flock on the
    primary file, so concurrent threads and concurrent processes can't break
    the chain.
    """

    _lock = threading.Lock()

    def __init__(self, path: Path | str, replicas: Optional[List[Path | str]] = None) -> None:
        self.path = Path(path)
        self.replicas = [Path(r) for r in (replicas or [])]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        for f in [self.path, *self.replicas]:
            if not f.exists():
                fd = os.open(str(f), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
        self._seq, self._prev = self._tail(self.path)

    @staticmethod
    def _tail(path: Path) -> Tuple[int, str]:
        """Resume from the last line without re-reading more than needed."""
        seq, prev = 0, GENESIS
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    seq, prev = entry["seq"], entry["digest"]
        return seq, prev

    def append(self, record: dict) -> str:
        """Seal a record into the chain and all replicas. Returns the digest."""
        with self._lock:
            # Take the kernel-level lock on the primary file so separate
            # processes serialize too; re-read the tail in case another
            # process appended while we waited.
            with self.path.open("a+", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    self._seq, self._prev = self._tail(self.path)
                    seq = self._seq + 1
                    digest = _digest(seq, self._prev, record)
                    line = json.dumps({"seq": seq, "prev": self._prev, "digest": digest,
                                       "record": record}, ensure_ascii=False) + "\n"
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
                    for replica in self.replicas:
                        with replica.open("a", encoding="utf-8") as rfh:
                            rfh.write(line)
                    self._seq, self._prev = seq, digest
                    return digest
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # -- verification --------------------------------------------------------

    @staticmethod
    def verify(path: Path | str) -> Tuple[bool, str]:
        """Check one chain file for internal integrity."""
        path = Path(path)
        if not path.exists():
            return True, "no ledger yet"
        seq, prev = 0, GENESIS
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, f"line {lineno}: corrupt JSON"
            if not isinstance(entry, dict):
                return False, f"line {lineno}: entry is not an object"
            seq += 1
            if entry.get("seq") != seq:
                return False, f"line {lineno}: sequence break (expected {seq})"
            if entry.get("prev") != prev:
                return False, f"line {lineno}: chain link broken"
            if entry.get("digest") != _digest(seq, prev, entry.get("record", {})):
                return False, f"line {lineno}: digest mismatch — record altered"
            prev = entry["digest"]
        return True, f"chain intact ({seq} entries)"


def verify_pair(alerts_path: Path | str, seal_path: Path | str) -> Tuple[bool, str]:
    """Verify the seal chain *and* that it matches the plain alert log."""
    ok, detail = SealedLedger.verify(seal_path)
    if not ok:
        return ok, detail
    if not Path(seal_path).exists() and Path(alerts_path).exists():
        return False, "alert log exists but no seal — ledger missing"
    alerts_path = Path(alerts_path)
    seal_path = Path(seal_path)
    plain = [l for l in alerts_path.read_text(encoding="utf-8").splitlines()
             if l.strip()] if alerts_path.exists() else []
    sealed = [json.loads(l)["record"] for l in
              seal_path.read_text(encoding="utf-8").splitlines() if l.strip()
              ] if seal_path.exists() else []
    if len(plain) != len(sealed):
        return False, f"alert log has {len(plain)} entries, seal has {len(sealed)}"
    for i, (p, s) in enumerate(zip(plain, sealed), 1):
        if json.loads(p) != s:
            return False, f"entry {i}: alert log diverges from seal"
    return True, f"seal verified and matches alert log ({len(sealed)} entries)"


def recover(primary: Path | str, sources: List[Path | str]) -> Tuple[bool, str]:
    """Rebuild a lost/corrupt primary seal from the best surviving replica."""
    primary = Path(primary)
    best: Optional[Path] = None
    best_count = -1
    for src in sources:
        src = Path(src)
        ok, _ = SealedLedger.verify(src)
        if ok and src.exists():
            count = sum(1 for l in src.read_text(encoding="utf-8").splitlines() if l.strip())
            if count > best_count:
                best, best_count = src, count
    if best is None:
        return False, "no intact replica found"
    fd = os.open(str(primary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(best.read_text(encoding="utf-8"))
    return True, f"recovered {best_count} entries from {best}"
