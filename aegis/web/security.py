"""Security primitives for the Aegis web layer.

- Single-user API token, generated on first run, stored with 0600 perms.
- Constant-time token comparison (no timing oracle).
- Sliding-window rate limiter (in-memory, per-client).
- Brute-force lockout on repeated auth failures.
- Strict HTTP security headers middleware.
"""

from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, Tuple

TOKEN_PATH_DEFAULT = Path.home() / ".aegis" / "api_token"


def load_or_create_token(path: Path | str = TOKEN_PATH_DEFAULT) -> str:
    """Return the API token, generating a random 256-bit one on first run.

    The token file is created with 0600 permissions inside a 0700 directory.
    """
    path = Path(path)
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise RuntimeError(f"token file {path} looks corrupt; delete it to regenerate")
        return token
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    token = secrets.token_hex(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    return token


def check_token(provided: str, expected: str) -> bool:
    """Constant-time comparison — never short-circuits on length mismatch."""
    return hmac.compare_digest(provided.encode(), expected.encode())


class RateLimiter:
    """Sliding-window rate limiter, keyed by client identifier."""

    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True


class AuthLockout:
    """Locks a client out after too many failed auth attempts."""

    def __init__(self, max_failures: int = 5, lockout_seconds: float = 300.0) -> None:
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._state: Dict[str, Tuple[int, float]] = {}
        self._lock = threading.Lock()

    def is_locked(self, key: str) -> bool:
        with self._lock:
            failures, until = self._state.get(key, (0, 0.0))
            return failures >= self.max_failures and time.monotonic() < until

    def record_failure(self, key: str) -> None:
        with self._lock:
            failures, _ = self._state.get(key, (0, 0.0))
            self._state[key] = (failures + 1, time.monotonic() + self.lockout_seconds)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
    "Cache-Control": "no-store",
}


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware that stamps security headers on every response."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers") or [])
                for name, value in SECURITY_HEADERS.items():
                    headers[name.lower().encode()] = value.encode()
                # Strip any Server header — don't advertise the stack.
                headers.pop(b"server", None)
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_headers)
