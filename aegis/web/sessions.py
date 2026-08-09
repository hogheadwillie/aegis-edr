"""Server-side session store for the dashboard.

Sessions are random 256-bit IDs kept only in server memory. The browser
holds an opaque, HttpOnly, SameSite=Strict cookie — no token material ever
reaches JavaScript. Each session carries its own CSRF token, required on
every state-changing form POST.

Hardening:
- Sliding expiration: activity extends the session, idle sessions die.
- Per-user session cap: a 6th login evicts the oldest session of that user,
  bounding the footprint of stolen cookies.
- destroy_all(username): revoke every session of an account at once
  (used on password change, and available for incident response).
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Dict, Optional, Tuple

SESSION_COOKIE = "aegis_session"
SECURE_SESSION_COOKIE = "__Host-aegis_session"  # requires Secure, Path=/, no Domain
DEFAULT_TTL_SECONDS = 12 * 3600
MAX_SESSIONS_PER_USER = 5


class SessionStore:
    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 max_sessions: int = 10_000,
                 max_per_user: int = MAX_SESSIONS_PER_USER) -> None:
        self.ttl = ttl_seconds
        self.max_sessions = max_sessions
        self.max_per_user = max_per_user
        self._sessions: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, username: str = "", role: str = "") -> Tuple[str, str]:
        """Return (session_id, csrf_token), bound to a user identity."""
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self._lock:
            self._sweep_locked()
            if len(self._sessions) >= self.max_sessions:
                raise RuntimeError("too many active sessions")
            self._evict_over_cap_locked(username)
            self._sessions[sid] = {"expires": time.monotonic() + self.ttl,
                                   "created": time.monotonic(),
                                   "csrf": csrf, "username": username, "role": role}
        return sid, csrf

    def validate(self, sid: Optional[str]) -> Optional[dict]:
        """Return the session dict if the id is live, else None.

        Successful validation slides the expiry forward — active users are
        never cut off mid-work, idle ones time out on schedule.
        """
        if not sid:
            return None
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            now = time.monotonic()
            if now > session["expires"]:
                self._sessions.pop(sid, None)
                return None
            session["expires"] = now + self.ttl
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

    def destroy_all(self, username: str, keep_sid: Optional[str] = None) -> int:
        """Revoke every session owned by *username* (optionally keeping one)."""
        with self._lock:
            doomed = [sid for sid, s in self._sessions.items()
                      if s["username"] == username and sid != keep_sid]
            for sid in doomed:
                del self._sessions[sid]
        return len(doomed)

    def _evict_over_cap_locked(self, username: str) -> None:
        owned = sorted(
            (s["created"], sid) for sid, s in self._sessions.items()
            if s["username"] == username)
        for _created, sid in owned[:max(0, len(owned) - self.max_per_user + 1)]:
            del self._sessions[sid]

    def _sweep_locked(self) -> None:
        now = time.monotonic()
        expired = [sid for sid, s in self._sessions.items() if now > s["expires"]]
        for sid in expired:
            del self._sessions[sid]
