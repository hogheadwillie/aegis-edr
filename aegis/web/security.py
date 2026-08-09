"""Security primitives for the Aegis web layer.

- Single-user API token, generated on first run, stored with 0600 perms.
- Constant-time token comparison (no timing oracle).
- Sliding-window rate limiter (in-memory, per-client).
- Brute-force lockout on repeated auth failures.
- Strict HTTP security headers middleware (CSP, COOP/CORP, Permissions-Policy).
- Origin/Referer enforcement on state-changing requests (CSRF layer two).
- Request body size cap (413 before any parsing happens).
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
from urllib.parse import urlsplit

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
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()"
    ),
    # Cross-origin isolation: our pages must not be embeddable or reusable
    # by foreign origins (Spectre-class + clickjacking defense in depth).
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; font-src 'self'; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
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


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class OriginCheckMiddleware:
    """Reject cross-origin state-changing requests at the edge.

    The per-session CSRF token is the primary defense; this is layer two.
    A browser-driven cross-site POST always carries an Origin (or at least a
    Referer) header — if either is present and points at a foreign host, the
    request is refused with 403 before reaching any route. Header-less
    requests (curl, scripts) are allowed through and remain subject to
    bearer-token / session auth as usual.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and scope.get("method") not in SAFE_METHODS:
            headers = {k.decode().lower(): v.decode()
                       for k, v in scope.get("headers", [])}
            host = headers.get("host", "")
            for source in ("origin", "referer"):
                value = headers.get(source)
                if value:
                    origin_host = urlsplit(value).netloc
                    # netloc includes the port; compare case-insensitively.
                    if host and origin_host.lower() != host.lower():
                        await self._forbid(send)
                        return
        await self.app(scope, receive, send)

    @staticmethod
    async def _forbid(send) -> None:
        body = b"cross-origin request refused"
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"text/plain"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


MAX_BODY_BYTES = 64 * 1024  # the UI/API never accepts payloads beyond 64 KiB


class RequestSizeLimitMiddleware:
    """413 any request whose declared body exceeds MAX_BODY_BYTES.

    Checked before routing, so oversized posts can't burn CPU on parsing
    (the brute-force surface stays tiny). Requests that omit Content-Length
    (chunked or empty-body API clients like curl) are allowed through.
    """

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and scope.get("method") not in SAFE_METHODS:
            headers = {k.decode().lower(): v.decode()
                       for k, v in scope.get("headers", [])}
            length = headers.get("content-length")
            if length is not None and (not length.isdigit()
                                       or int(length) > self.max_bytes):
                await self._too_large(send)
                return
        await self.app(scope, receive, send)

    @staticmethod
    async def _too_large(send) -> None:
        body = b"request body too large"
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"text/plain"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
