"""Server-side session store for the dashboard.

Sessions are random 256-bit IDs kept only in server memory. The browser
holds an opaque, HttpOnly, SameSite=Strict cookie — no token material ever
reaches JavaScript. Each session carries its own CSRF token, required on
every state-changing form POST.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Dict, Optional, Tuple

SESSION_COOKIE = "aegis_session"
DEFAULT_TTL_SECONDS = 12 * 3600


class SessionStore:
    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 max_sessions: int = 10_000) -> None:
        self.ttl = ttl_seconds
        self.max_sessions = max_sessions
        self._sessions: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self) -> Tuple[str, str]:
        """Return (session_id, csrf_token)."""
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self._lock:
            self._sweep_locked()
            if len(self._sessions) >= self.max_sessions:
                raise RuntimeError("too many active sessions")
            self._sessions[sid] = {"expires": time.monotonic() + self.ttl, "csrf": csrf}
        return sid, csrf

    def validate(self, sid: Optional[str]) -> Optional[dict]:
        """Return the session dict if the id is live, else None."""
        if not sid:
            return None
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            if time.monotonic() > session["expires"]:
                self._sessions.pop(sid, None)
                return None
            return session

    def check_csrf(self, sid: Optional[str], presented: Optional[str]) -> bool:
        session = self.validate(sid)
        if session is None or not presented:
            return False
        return secrets.compare_digest(session["csrf"], presented)

    def destroy(self, sid: Optional[str]) -> None:
        if sid:
            with self._lock:
                self._sessions.pop(sid, None)

    def _sweep_locked(self) -> None:
        now = time.monotonic()
        expired = [sid for sid, s in self._sessions.items() if now > s["expires"]]
        for sid in expired:
            del self._sessions[sid]
