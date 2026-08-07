"""FastAPI backend for the Aegis EDR console — pure-Python, server-rendered.

Two surfaces:
- Browser UI: server-rendered Jinja2 pages behind a session cookie
  (HttpOnly, SameSite=Strict) with per-session CSRF tokens on every POST.
  No JavaScript anywhere in the stack.
- JSON API (/api/*): bearer-token auth for scripts and integrations.

Security posture:
- Constant-time token comparison (login and bearer).
- Per-IP sliding-window rate limiting + brute-force lockout on failures.
- Security headers on all responses (strict CSP, nosniff, frame-deny, no-store).
- No CORS, no docs/openapi, pydantic-validated inputs, path-traversal guards.
- Binds to 127.0.0.1 by default; refuses remote binds without --allow-remote.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import List, Literal, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from ..agent import Agent, hostname
from ..alerts import SEVERITY_RANK, AlertSink, load_alerts
from ..detection.engine import DetectionEngine, load_iocs, load_rules
from ..monitors import fim as fim_mod
from .audit import log_event, load_events
from .auth import UserStore
from .security import (AuthLockout, RateLimiter, SecurityHeadersMiddleware,
                       check_token, load_or_create_token)
from .sessions import SESSION_COOKIE, SessionStore

STATIC_DIR = Path(__file__).resolve().parent / "static"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "default_rules.json"
AEGIS_HOME = Path.home() / ".aegis"
IOC_VALUE_RE = re.compile(r"^[\w.\-:]+$")

_bearer = HTTPBearer(auto_error=False)


class IocIn(BaseModel):
    category: Literal["ip", "domain", "sha256"]
    value: str = Field(min_length=1, max_length=256, pattern=r"^[\w.\-:]+$")


class ScanOut(BaseModel):
    alerts_created: int
    alerts: List[dict]


def _subject_of(alert) -> str:
    e = alert.event or {}
    return (e.get("cmdline") or e.get("path")
            or f"{e.get('process', '?')} -> {e.get('remote_ip', '?')}"
               f"{':' + str(e['remote_port']) if e.get('remote_port') else ''}")


def create_app(token_path: Path | str | None = None,
               rules_path: Path | str | None = None,
               secure_cookies: bool = False) -> FastAPI:
    token = load_or_create_token(token_path) if token_path else load_or_create_token()
    rules_file = Path(rules_path) if rules_path else RULES_PATH
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

    app = FastAPI(title="Aegis EDR", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeadersMiddleware)
    limiter = RateLimiter(max_requests=120, window_seconds=60.0)
    lockout = AuthLockout(max_failures=5, lockout_seconds=300.0)
    sessions = SessionStore()
    users = UserStore(AEGIS_HOME / "users.json")
    audit_path = AEGIS_HOME / "audit.jsonl"

    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _throttle(request: Request) -> str:
        ip = _client_ip(request)
        if not limiter.allow(ip):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded")
        if lockout.is_locked(ip):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "locked out after repeated auth failures")
        return ip

    # -- JSON API auth -------------------------------------------------------

    def require_auth(request: Request,
                     creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> None:
        ip = _throttle(request)
        if creds is None or not check_token(creds.credentials, token):
            lockout.record_failure(ip)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing token")
        lockout.record_success(ip)

    # -- browser session helpers ----------------------------------------------

    def _session(request: Request) -> Optional[dict]:
        return sessions.validate(request.cookies.get(SESSION_COOKIE))

    def _require_session(request: Request) -> dict:
        _throttle(request)
        session = _session(request)
        if session is None:
            raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": "/"})
        return session

    def _require_csrf(request: Request, csrf: str) -> dict:
        session = _require_session(request)
        if not sessions.check_csrf(request.cookies.get(SESSION_COOKIE), csrf):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "bad CSRF token")
        return session

    def _redirect_console(notice: str = "") -> RedirectResponse:
        location = "/console" + (f"?notice={notice}" if notice else "")
        return RedirectResponse(location, status_code=status.HTTP_303_SEE_OTHER)

    # -- data helpers ----------------------------------------------------------

    def _engine() -> DetectionEngine:
        return DetectionEngine(load_rules(rules_file), load_iocs(AEGIS_HOME / "iocs.json"),
                               host=hostname())

    def _agent(echo: bool = False) -> Agent:
        return Agent(_engine(), AlertSink(AEGIS_HOME / "alerts.jsonl", echo=echo))

    def _stats() -> dict:
        alerts = load_alerts(AEGIS_HOME / "alerts.jsonl")
        by_sev = {s: 0 for s in SEVERITY_RANK}
        for a in alerts:
            by_sev[a.severity] += 1
        return {"host": hostname(), "total_alerts": len(alerts), "by_severity": by_sev}

    def _write_iocs(iocs: dict) -> None:
        path = AEGIS_HOME / "iocs.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({k: sorted(v) for k, v in iocs.items()}, indent=2),
                        encoding="utf-8")
        os.chmod(path, 0o600)

    # ======================================================================
    # Browser UI (server-rendered, session + CSRF)
    # ======================================================================

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index(request: Request) -> Response:
        _throttle(request)
        if _session(request) is not None:
            return RedirectResponse("/console", status_code=status.HTTP_303_SEE_OTHER)
        mode = "users" if users.count() > 0 else "token"
        return templates.TemplateResponse(request, "login.html",
                                          {"error": None, "mode": mode})

    @app.post("/login", response_class=HTMLResponse, include_in_schema=False)
    def login(request: Request,
              username: str = Form(default="", max_length=64),
              password: str = Form(default="", max_length=256),
              token: str = Form(default="", max_length=256)) -> Response:
        ip = _throttle(request)
        mode = "users" if users.count() > 0 else "token"

        def deny(msg: str) -> Response:
            lockout.record_failure(ip)
            log_event(audit_path, username or "(token)", "login_failed", msg)
            return templates.TemplateResponse(
                request, "login.html", {"error": msg, "mode": mode},
                status_code=status.HTTP_401_UNAUTHORIZED)

        if mode == "users":
            user = users.verify(username.strip(), password) if username and password else None
            if user is None:
                return deny("Invalid username or password.")
            sid, _csrf = sessions.create(username=user.username, role=user.role)
            log_event(audit_path, user.username, "login", "")
        else:
            if not token or not check_token(token, load_or_create_token()):
                return deny("Invalid token — access denied.")
            sid, _csrf = sessions.create(username="(token)", role="admin")

        lockout.record_success(ip)
        response = RedirectResponse("/console", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(SESSION_COOKIE, sid, max_age=int(sessions.ttl),
                            httponly=True, samesite="strict", secure=secure_cookies)
        return response

    @app.post("/logout", include_in_schema=False)
    def logout(request: Request) -> RedirectResponse:
        sessions.destroy(request.cookies.get(SESSION_COOKIE))
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE)
        return response

    @app.get("/console", response_class=HTMLResponse, include_in_schema=False)
    def console(request: Request, severity: Optional[str] = None,
                notice: Optional[str] = None, ioc_error: Optional[str] = None) -> Response:
        session = _require_session(request)
        if severity is not None and severity not in SEVERITY_RANK:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "bad severity")

        alerts = load_alerts(AEGIS_HOME / "alerts.jsonl")
        if severity:
            cutoff = SEVERITY_RANK[severity]
            alerts = [a for a in alerts if SEVERITY_RANK[a.severity] >= cutoff]
        alerts = alerts[-200:][::-1]
        alert_rows = [
            {"timestamp": a.timestamp, "severity": a.severity, "rule_id": a.rule_id,
             "name": a.name, "subject": _subject_of(a), "mitre": a.mitre}
            for a in alerts]

        rules = load_rules(rules_file)
        rule_rows = [{"id": r.id, "name": r.name, "severity": r.severity, "mitre": r.mitre}
                     for r in rules]
        iocs = {k: sorted(v) for k, v in load_iocs(AEGIS_HOME / "iocs.json").items()}

        user = {"username": session.get("username", ""), "role": session.get("role", "")}
        user_rows = users.list_users()
        admin_count = sum(1 for u in user_rows if u.role == "admin")
        audit_rows = load_events(audit_path, limit=100) if user["role"] == "admin" else []

        return templates.TemplateResponse(request, "console.html", {
            "stats": _stats(), "alerts": alert_rows, "rules": rule_rows, "iocs": iocs,
            "severity": severity, "notice": notice, "ioc_error": ioc_error,
            "csrf": session["csrf"], "user": user, "users": [u.to_dict() for u in user_rows],
            "admin_count": admin_count, "audit": audit_rows,
        })

    @app.post("/ui/scan", include_in_schema=False)
    def ui_scan(request: Request, csrf: str = Form(default="")) -> RedirectResponse:
        _require_csrf(request, csrf)
        alerts = _agent().full_scan()
        return _redirect_console(f"Scan complete: {len(alerts)} new alert(s).")

    @app.post("/ui/iocs/add", include_in_schema=False)
    def ui_iocs_add(request: Request, csrf: str = Form(default=""),
                    category: str = Form(default=""),
                    value: str = Form(default="")) -> RedirectResponse:
        _require_csrf(request, csrf)  # CSRF check precedes all input handling
        value = value.strip()
        if category not in ("ip", "domain", "sha256") or not IOC_VALUE_RE.match(value) \
                or len(value) > 256:
            return _redirect_console()
        iocs = load_iocs(AEGIS_HOME / "iocs.json")
        iocs.setdefault(category, set()).add(value)
        _write_iocs(iocs)
        return _redirect_console()

    @app.post("/ui/iocs/remove", include_in_schema=False)
    def ui_iocs_remove(request: Request, csrf: str = Form(default=""),
                       category: str = Form(default=""),
                       value: str = Form(default="")) -> RedirectResponse:
        session = _require_csrf(request, csrf)
        if category in ("ip", "domain", "sha256"):
            iocs = load_iocs(AEGIS_HOME / "iocs.json")
            iocs.setdefault(category, set()).discard(value)
            _write_iocs(iocs)
            log_event(audit_path, session.get("username", "?"), "ioc_remove", value[:120])
        return _redirect_console()

    # -- user administration (admin only) -------------------------------------

    def _require_admin(request: Request, csrf: str) -> dict:
        session = _require_csrf(request, csrf)
        if session.get("role") != "admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
        return session

    @app.post("/ui/users/add", include_in_schema=False)
    def ui_users_add(request: Request, csrf: str = Form(default=""),
                     username: str = Form(default="", max_length=32),
                     password: str = Form(default="", max_length=256),
                     role: str = Form(default="")) -> RedirectResponse:
        session = _require_admin(request, csrf)
        try:
            users.add_user(username, password, role)
            log_event(audit_path, session.get("username", "?"), "user_add", username.strip())
        except ValueError:
            pass  # invalid input or duplicate — silently refused
        return _redirect_console()

    @app.post("/ui/users/remove", include_in_schema=False)
    def ui_users_remove(request: Request, csrf: str = Form(default=""),
                        username: str = Form(default="", max_length=32)) -> RedirectResponse:
        session = _require_admin(request, csrf)
        try:
            users.remove_user(username.strip())
            log_event(audit_path, session.get("username", "?"), "user_remove", username.strip())
        except ValueError:
            pass  # unknown user or last admin — refused
        return _redirect_console()

    # ======================================================================
    # JSON API (bearer token, unchanged)
    # ======================================================================

    @app.post("/api/auth/verify", status_code=204, response_class=Response)
    def verify(_: None = Depends(require_auth)) -> Response:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/alerts")
    def get_alerts(severity: Optional[str] = None, limit: int = 200,
                   _: None = Depends(require_auth)) -> dict:
        limit = max(1, min(limit, 1000))
        alerts = load_alerts(AEGIS_HOME / "alerts.jsonl")
        if severity:
            if severity not in SEVERITY_RANK:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "bad severity")
            cutoff = SEVERITY_RANK[severity]
            alerts = [a for a in alerts if SEVERITY_RANK[a.severity] >= cutoff]
        alerts = alerts[-limit:][::-1]
        return {"total": len(alerts), "alerts": [a.to_dict() for a in alerts]}

    @app.post("/api/scan", response_model=ScanOut)
    def run_scan(_: None = Depends(require_auth)) -> dict:
        alerts = _agent().full_scan()
        return {"alerts_created": len(alerts), "alerts": [a.to_dict() for a in alerts]}

    @app.post("/api/fim/check")
    def fim_check(directory: str, _: None = Depends(require_auth)) -> dict:
        root = Path(directory).expanduser().resolve()
        if not root.is_dir():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "directory does not exist")
        key = hashlib.sha256(str(root).encode()).hexdigest()[:12]
        baseline_path = AEGIS_HOME / "fim" / f"{key}.json"
        try:
            baseline = fim_mod.load_baseline(baseline_path)
        except FileNotFoundError:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "no baseline for this directory; create one via the CLI")
        events = fim_mod.diff_baseline(baseline, root)
        alerts = _agent()._dispatch(_engine().evaluate_all(events))
        return {"alerts_created": len(alerts), "alerts": [a.to_dict() for a in alerts]}

    @app.get("/api/rules")
    def get_rules(_: None = Depends(require_auth)) -> dict:
        rules = load_rules(rules_file)
        return {"total": len(rules), "rules": [
            {"id": r.id, "name": r.name, "severity": r.severity,
             "event_type": r.event_type, "description": r.description,
             "mitre": r.mitre, "enabled": r.enabled} for r in rules]}

    @app.get("/api/stats")
    def get_stats(_: None = Depends(require_auth)) -> dict:
        return _stats()

    @app.get("/api/iocs")
    def get_iocs(_: None = Depends(require_auth)) -> dict:
        iocs = load_iocs(AEGIS_HOME / "iocs.json")
        return {k: sorted(v) for k, v in iocs.items()}

    @app.post("/api/iocs", status_code=201)
    def add_ioc(payload: IocIn, _: None = Depends(require_auth)) -> dict:
        iocs = load_iocs(AEGIS_HOME / "iocs.json")
        iocs.setdefault(payload.category, set()).add(payload.value)
        _write_iocs(iocs)
        return {"added": payload.value, "category": payload.category}

    @app.delete("/api/iocs")
    def remove_ioc(payload: IocIn, _: None = Depends(require_auth)) -> dict:
        iocs = load_iocs(AEGIS_HOME / "iocs.json")
        iocs.setdefault(payload.category, set()).discard(payload.value)
        _write_iocs(iocs)
        return {"removed": payload.value, "category": payload.category}

    # -- static assets (CSS only; no JS exists anymore) ------------------------

    @app.get("/static/{filename}", include_in_schema=False)
    def static_files(filename: str) -> FileResponse:
        if "/" in filename or "\\" in filename or filename.startswith("."):
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        target = (STATIC_DIR / filename).resolve()
        if not target.is_file() or STATIC_DIR not in target.parents:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return FileResponse(target)

    return app


def serve(host: str = "127.0.0.1", port: int = 8765, allow_remote: bool = False,
          rules_path: Path | str | None = None, secure_cookies: bool = False) -> None:
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise SystemExit(
            f"refusing to bind to {host!r} without --allow-remote: "
            "the dashboard has single-token auth and no TLS by default"
        )
    app = create_app(rules_path=rules_path, secure_cookies=secure_cookies)
    token_hint = Path.home() / ".aegis" / "api_token"
    print(f"Aegis EDR dashboard: http://{host}:{port}")
    print(f"API token: {token_hint} (paste it into the login page)")
    uvicorn.run(app, host=host, port=port, log_level="warning", server_header=False)
