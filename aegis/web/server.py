"""FastAPI backend for the Aegis EDR dashboard.

Security posture:
- Every /api route requires the bearer token (constant-time check).
- Per-IP sliding-window rate limiting + brute-force lockout on auth failures.
- Security headers on all responses (CSP, nosniff, frame-deny, no-store).
- No CORS — the dashboard is served same-origin only.
- Pydantic-validated inputs; FIM paths resolved and must exist on disk.
- Binds to 127.0.0.1 by default; refuses 0.0.0.0 without --allow-remote.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..agent import Agent, hostname
from ..alerts import SEVERITY_RANK, AlertSink, load_alerts
from ..detection.engine import DetectionEngine, load_iocs, load_rules
from ..monitors import fim as fim_mod
from .security import (AuthLockout, RateLimiter, SecurityHeadersMiddleware,
                       check_token, load_or_create_token)

STATIC_DIR = Path(__file__).resolve().parent / "static"
RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "default_rules.json"
AEGIS_HOME = Path.home() / ".aegis"

_bearer = HTTPBearer(auto_error=False)


class IocIn(BaseModel):
    category: Literal["ip", "domain", "sha256"]
    value: str = Field(min_length=1, max_length=256, pattern=r"^[\w.\-:]+$")


class ScanOut(BaseModel):
    alerts_created: int
    alerts: List[dict]


def create_app(token_path: Path | str | None = None,
               rules_path: Path | str | None = None) -> FastAPI:
    token = load_or_create_token(token_path) if token_path else load_or_create_token()
    rules_file = Path(rules_path) if rules_path else RULES_PATH

    app = FastAPI(title="Aegis EDR", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeadersMiddleware)
    limiter = RateLimiter(max_requests=120, window_seconds=60.0)
    lockout = AuthLockout(max_failures=5, lockout_seconds=300.0)

    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def require_auth(request: Request,
                     creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> None:
        ip = _client_ip(request)
        if not limiter.allow(ip):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded")
        if lockout.is_locked(ip):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "locked out after repeated auth failures")
        if creds is None or not check_token(creds.credentials, token):
            lockout.record_failure(ip)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing token")
        lockout.record_success(ip)

    def _engine() -> DetectionEngine:
        return DetectionEngine(load_rules(rules_file), load_iocs(AEGIS_HOME / "iocs.json"),
                               host=hostname())

    def _agent(echo: bool = False) -> Agent:
        return Agent(_engine(), AlertSink(AEGIS_HOME / "alerts.jsonl", echo=echo))

    # -- auth probe ---------------------------------------------------------

    @app.post("/api/auth/verify", status_code=204, response_class=Response)
    def verify(_: None = Depends(require_auth)) -> Response:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # -- alerts -------------------------------------------------------------

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
        alerts = alerts[-limit:][::-1]  # newest first
        return {"total": len(alerts), "alerts": [a.to_dict() for a in alerts]}

    # -- scans --------------------------------------------------------------

    @app.post("/api/scan", response_model=ScanOut)
    def run_scan(_: None = Depends(require_auth)) -> dict:
        alerts = _agent().full_scan()
        return {"alerts_created": len(alerts), "alerts": [a.to_dict() for a in alerts]}

    @app.post("/api/fim/check")
    def fim_check(directory: str, _: None = Depends(require_auth)) -> dict:
        # Resolve to an absolute path; must be an existing directory.
        root = Path(directory).expanduser().resolve()
        if not root.is_dir():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "directory does not exist")
        key = __import__("hashlib").sha256(str(root).encode()).hexdigest()[:12]
        baseline_path = AEGIS_HOME / "fim" / f"{key}.json"
        try:
            baseline = fim_mod.load_baseline(baseline_path)
        except FileNotFoundError:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "no baseline for this directory; create one via the CLI")
        events = fim_mod.diff_baseline(baseline, root)
        alerts = _agent()._dispatch(_engine().evaluate_all(events))
        return {"alerts_created": len(alerts), "alerts": [a.to_dict() for a in alerts]}

    # -- rules / stats / IOCs ------------------------------------------------

    @app.get("/api/rules")
    def get_rules(_: None = Depends(require_auth)) -> dict:
        rules = load_rules(rules_file)
        return {"total": len(rules), "rules": [
            {"id": r.id, "name": r.name, "severity": r.severity,
             "event_type": r.event_type, "description": r.description,
             "mitre": r.mitre, "enabled": r.enabled} for r in rules]}

    @app.get("/api/stats")
    def get_stats(_: None = Depends(require_auth)) -> dict:
        alerts = load_alerts(AEGIS_HOME / "alerts.jsonl")
        by_sev = {s: 0 for s in SEVERITY_RANK}
        for a in alerts:
            by_sev[a.severity] += 1
        return {"host": hostname(), "total_alerts": len(alerts), "by_severity": by_sev}

    @app.get("/api/iocs")
    def get_iocs(_: None = Depends(require_auth)) -> dict:
        iocs = load_iocs(AEGIS_HOME / "iocs.json")
        return {k: sorted(v) for k, v in iocs.items()}

    @app.post("/api/iocs", status_code=201)
    def add_ioc(payload: IocIn, _: None = Depends(require_auth)) -> dict:
        path = AEGIS_HOME / "iocs.json"
        iocs = load_iocs(path)
        iocs.setdefault(payload.category, set()).add(payload.value)
        path.parent.mkdir(parents=True, exist_ok=True)
        import json, os
        path.write_text(json.dumps({k: sorted(v) for k, v in iocs.items()}, indent=2),
                        encoding="utf-8")
        os.chmod(path, 0o600)
        return {"added": payload.value, "category": payload.category}

    @app.delete("/api/iocs")
    def remove_ioc(payload: IocIn, _: None = Depends(require_auth)) -> dict:
        path = AEGIS_HOME / "iocs.json"
        iocs = load_iocs(path)
        iocs.setdefault(payload.category, set()).discard(payload.value)
        import json
        path.write_text(json.dumps({k: sorted(v) for k, v in iocs.items()}, indent=2),
                        encoding="utf-8")
        return {"removed": payload.value, "category": payload.category}

    # -- dashboard (same-origin static) --------------------------------------

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/static/{filename}", include_in_schema=False)
    def static_files(filename: str) -> FileResponse:
        # Guard against path traversal: only plain filenames under static/.
        if "/" in filename or "\\" in filename or filename.startswith("."):
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        target = (STATIC_DIR / filename).resolve()
        if not target.is_file() or STATIC_DIR not in target.parents:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return FileResponse(target)

    return app


def serve(host: str = "127.0.0.1", port: int = 8765, allow_remote: bool = False,
          rules_path: Path | str | None = None) -> None:
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise SystemExit(
            f"refusing to bind to {host!r} without --allow-remote: "
            "the dashboard has single-token auth and no TLS by default"
        )
    app = create_app(rules_path=rules_path)
    token_hint = Path.home() / ".aegis" / "api_token"
    print(f"Aegis EDR dashboard: http://{host}:{port}")
    print(f"API token: {token_hint} (paste it into the dashboard login)")
    uvicorn.run(app, host=host, port=port, log_level="warning", server_header=False)
