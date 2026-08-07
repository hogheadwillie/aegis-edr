"""Multi-user account management with quantum-resistant password hashing.

Passwords are hashed with Argon2id (RFC 9106), the OWASP-recommended
memory-hard KDF. Its security rests on classical hardness assumptions that
Shor's algorithm does not touch, and Grover's algorithm only halves
symmetric security — at 64 MiB memory cost and 3 iterations, brute-force
search (classical or quantum) is computationally infeasible for any
non-trivial password. Hence "quantum-resistant passwords".

User records live in ~/.aegis/users.json (0600 in a 0700 dir). Only Argon2id
hashes are ever stored — plaintext passwords never touch the disk.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

ROLES = ("admin", "analyst")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
MIN_PASSWORD_LENGTH = 12

DEFAULT_USERS_PATH = Path.home() / ".aegis" / "users.json"

# OWASP-recommended interactive parameters: 64 MiB, 3 iterations, 4 lanes.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


@dataclass
class User:
    username: str
    role: str

    def to_dict(self) -> dict:
        return {"username": self.username, "role": self.role}


class UserStore:
    def __init__(self, path: Path | str = DEFAULT_USERS_PATH) -> None:
        self.path = Path(path)

    # -- persistence ---------------------------------------------------------

    def _load(self) -> Dict[str, dict]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, users: Dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(users, fh, indent=2)

    # -- queries --------------------------------------------------------------

    def count(self) -> int:
        return len(self._load())

    def list_users(self) -> List[User]:
        return [User(username=u, role=rec["role"]) for u, rec in sorted(self._load().items())]

    def get(self, username: str) -> Optional[User]:
        rec = self._load().get(username)
        return User(username=username, role=rec["role"]) if rec else None

    # -- mutations ------------------------------------------------------------

    def add_user(self, username: str, password: str, role: str) -> User:
        username = username.strip()
        if not USERNAME_RE.match(username):
            raise ValueError("username must be 3-32 chars of [a-zA-Z0-9_.-]")
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        users = self._load()
        if username in users:
            raise ValueError(f"user {username!r} already exists")
        users[username] = {"role": role, "pw": _hasher.hash(password)}
        self._save(users)
        return User(username=username, role=role)

    def remove_user(self, username: str) -> None:
        users = self._load()
        if username not in users:
            raise ValueError(f"no user {username!r}")
        if users[username]["role"] == "admin" and \
                sum(1 for u in users.values() if u["role"] == "admin") == 1:
            raise ValueError("cannot remove the last admin")
        del users[username]
        self._save(users)

    def change_password(self, username: str, new_password: str) -> None:
        if len(new_password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        users = self._load()
        if username not in users:
            raise ValueError(f"no user {username!r}")
        users[username]["pw"] = _hasher.hash(new_password)
        self._save(users)

    # -- authentication ---------------------------------------------------------

    def verify(self, username: str, password: str) -> Optional[User]:
        rec = self._load().get(username)
        if rec is None:
            return None
        try:
            if _hasher.verify(rec["pw"], password):
                return User(username=username, role=rec["role"])
        except (VerifyMismatchError, VerificationError, InvalidHash):
            pass
        return None


def generate_password(length: int = 20) -> str:
    """CSPRNG-generated password with mixed character classes."""
    alphabet = string.ascii_letters + string.digits + "-_.!#"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)):
            return pw
