# Aegis EDR

A host-based Endpoint Detection & Response (EDR) tool in Python, modeled on how platforms like CrowdStrike Falcon work: a lightweight agent monitors **processes, network connections, and file integrity**, matches observations against a **behavioral rule engine** mapped to MITRE ATT&CK, and produces **severity-scored alerts**. **Every line of executable code in this project is Python** — including the web console, which is server-rendered with zero JavaScript.

> **Defensive security tool.** Only run Aegis on hosts you own or are explicitly authorized to monitor. It performs no offensive actions — detection and logging only.

## Architecture

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Process    │   │  Network    │   │ File        │
│  monitor    │   │  monitor    │   │ integrity   │
│  (psutil)   │   │  (psutil)   │   │ (SHA-256)   │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       └─────────────────┼─────────────────┘
                         ▼  events
              ┌─────────────────────┐
              │  Detection engine   │  JSON rules: logic all/any,
              │  + IOC feed         │  ops: eq/in/contains/regex/in_ioc…
              └──────────┬──────────┘
                         ▼  alerts (low → critical)
              ┌─────────────────────┐
              │  Alert pipeline     │  console + JSONL log,
              │  ~/.aegis/alerts.*  │  session dedup, reporting
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  Web layer (pure    │  server-rendered console
              │  Python, no JS)     │  + bearer-token JSON API
              └─────────────────────┘
```

## Built-in detections (12 rules, MITRE-mapped)

| Rule | Detection | Severity | ATT&CK |
|------|-----------|----------|--------|
| PROC-001 | Execution from temp directory | high | T1059, T1070 |
| PROC-002 | Fileless / deleted-binary execution | critical | T1055, T1620 |
| PROC-003 | Obfuscated or encoded command line | high | T1027, T1140 |
| PROC-004 | Credential store access attempt | high | T1003, T1552 |
| PROC-005 | Download-and-execute cradle | medium | T1105, T1059 |
| NET-001 | Connection to known-malicious IP (IOC) | critical | T1071 |
| NET-002 | Connection on classic C2 port | medium | T1071, T1571 |
| NET-003 | Possible reverse shell | high | T1059, T1071 |
| NET-004 | Shell listening on network port | critical | T1059, T1571 |
| FIM-001 | Sensitive account/auth file changed | critical | T1098, T1136, T1556 |
| FIM-002 | New content in startup/persistence location | high | T1547, T1053 |
| FIM-003 | Executable written to temp directory | medium | T1070, T1059 |

## Usage

```bash
cd aegis

# one-shot scan of processes + network connections
python -m aegis scan

# continuous monitoring (poll every 5s, dedup within the session)
python -m aegis watch --interval 5

# file integrity monitoring
python -m aegis fim baseline /etc
python -m aegis fim check /etc

# IOC feed (IPs, domains, SHA-256)
python -m aegis ioc add --ip 203.0.113.66
python -m aegis ioc list

# summarize the alert log
python -m aegis report --severity high

# web console + REST API (localhost only, server-rendered, no JavaScript)
pip install ".[web]"
python -m aegis serve                    # http://127.0.0.1:8765
python -m aegis serve --secure-cookies   # when serving over HTTPS
```

Install as a package to get the `aegis` command: `pip install .`

Exit codes for scripting: `scan`/`fim check` return `2` when high-severity-or-above alerts fire — easy to wire into cron, CI, or a SOAR webhook.

## Writing custom rules

Drop JSON files in a directory and pass `--rules DIR`:

```json
{
  "id": "CUSTOM-001",
  "name": "Suspicious parent-child pair",
  "severity": "high",
  "event_type": "process",
  "description": "Office app spawned a shell.",
  "mitre": ["T1204"],
  "conditions": [
    {"field": "parent_name", "op": "contains_any", "value": ["winword", "excel", "soffice"]},
    {"field": "name", "op": "in", "value": ["bash", "sh", "cmd.exe", "powershell"]}
  ]
}
```

Operators: `eq`, `ne`, `gt`, `lt`, `in`, `contains`, `contains_any`, `startswith`,
`endswith`, `regex`, `exists`, `in_ioc`. Combine conditions with
`"logic": "all"` (default, AND) or `"any"` (OR).

## Running the tests

```bash
pip install pytest httpx
python -m pytest tests/ -v   # 57 tests (core + web security + multi-user auth)
```

## Managing accounts

```bash
python -m aegis user add alice --role admin           # generates a strong password
python -m aegis user add bob --role analyst --password '...'
python -m aegis user passwd alice                     # interactive change
python -m aegis user list
python -m aegis user remove bob                       # last admin is protected
```

## Deploying behind nginx (TLS termination)

For remote access, put the app behind nginx which owns HTTPS and forwards to
the loopback-bound app — configs included:

```bash
sudo deploy/nginx/gen-dev-cert.sh                 # self-signed lab cert
sudo cp deploy/nginx/aegis.conf /etc/nginx/sites-available/aegis
sudo ln -s /etc/nginx/sites-available/aegis /etc/nginx/sites-enabled/
python -m aegis user add admin1 --role admin      # create your accounts
python -m aegis serve --secure-cookies            # app stays on 127.0.0.1:8765
sudo nginx -t && sudo systemctl reload nginx
```

The config enforces TLS 1.2/1.3 only, HSTS, edge rate limiting on `/login`
and `/api/*`, 1 MB body cap, and HTTP→HTTPS redirect. Production: swap the dev
cert for Let's Encrypt (`certbot --nginx -d your.host`). For post-quantum key
exchange, OpenSSL 3.5 / nginx builds with ML-KEM (X25519MLKEM768) hybrid
groups make the TLS layer itself quantum-resistant — that lives at the proxy,
not the app.

## Web console & API security — pure Python, zero JavaScript

The web layer (`aegis serve`) is a fully server-rendered application: **every
line of executable code in this project is Python**. The dashboard is Jinja2
HTML rendered by FastAPI — there is no JavaScript anywhere in the stack.

**Browser UI (server-rendered)**
- **Multi-user accounts** with quantum-resistant password hashing: Argon2id (RFC 9106, OWASP parameters — 64 MiB, 3 iterations). Argon2id's security is unaffected by Shor's algorithm and Grover's only halves symmetric strength, so brute force stays infeasible for classical *and* quantum adversaries. Only hashes are ever stored (0600 file).
- Roles: `admin` (manage users, view audit log) and `analyst` (console only). Single-token mode remains until the first account is created (`aegis user add <name> --role admin`); the last admin cannot be removed.
- Audit trail: logins, failed logins, user/IOC changes appended to `~/.aegis/audit.jsonl` (0600).
- The browser only holds an opaque session cookie — `HttpOnly`, `SameSite=Strict`, 12 h expiry, `Secure` with `--secure-cookies`
- Per-session CSRF tokens required on every form POST (scan, IOC add/remove, user admin), verified before any input handling
- Jinja2 autoescaping makes all rendered alert/rule/IOC data XSS-safe by default
- Post/Redirect/Get pattern throughout — no resubmission pitfalls

**JSON API (`/api/*`, for scripts)**
- Bearer-token auth on every route, 256-bit token generated on first run and stored `0600` in a `0700` directory
- Constant-time token comparison (`hmac.compare_digest`) — no timing oracle

**Shared defenses**
- Per-IP sliding-window rate limiting (120 req/min) and brute-force lockout (5 failures → 5 min) on both surfaces
- Security headers on every response: strict CSP (`script-src 'self'`, `frame-ancestors 'none'`), `nosniff`, `DENY` framing, `no-store`, `Server` header stripped
- No CORS (same-origin only), no `docs`/`openapi.json` exposed, validated inputs, path-traversal guards on static files and FIM directories
- Binds to `127.0.0.1` by default; refuses non-loopback binds without `--allow-remote`

**Core hardening (applies to the CLI too)**
- Alert log, IOC store, FIM baselines, users file, and API token are written `0600` inside `0700` directories
- Rule files: 5 MB size cap, 10k rule cap, strict schema validation

### API endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/auth/verify` | token check (login) |
| GET | `/api/alerts?severity=&limit=` | alert feed, newest first |
| POST | `/api/scan` | run process + network scan |
| POST | `/api/fim/check?directory=` | FIM diff against baseline |
| GET | `/api/rules` | detection rule set |
| GET | `/api/stats` | severity counts + host |
| GET/POST/DELETE | `/api/iocs` | manage the IOC feed |

## Project layout

```
aegis/
├── aegis/
│   ├── agent.py              # orchestration, watch loop, dedup
│   ├── alerts.py             # alert model, JSONL sink, reporting loader
│   ├── cli.py                # scan / watch / fim / ioc / report / serve / user
│   ├── detection/engine.py   # rule matching + IOC store
│   ├── monitors/
│   │   ├── process.py        # process enumeration (incl. deleted-binary check)
│   │   ├── network.py        # connection/listener snapshot
│   │   └── fim.py            # SHA-256 baselines and diffing
│   ├── rules/default_rules.json
│   └── web/
│       ├── auth.py           # Argon2id multi-user accounts + roles
│       ├── audit.py          # audit trail (logins, user/IOC changes)
│       ├── security.py       # token mgmt, rate limiter, lockout, headers
│       ├── sessions.py       # server-side sessions + CSRF tokens
│       ├── server.py         # FastAPI: server-rendered UI + JSON API
│       ├── templates/        # login.html, console.html (Jinja2)
│       └── static/style.css  # the only non-Python asset (styling, not code)
├── deploy/nginx/             # TLS-terminating reverse proxy config + dev cert script
├── tests/test_aegis.py
├── tests/test_web.py
├── tests/test_users.py
└── pyproject.toml
```

## Honest limitations vs. a real EDR

Aegis demonstrates the *architecture* of an EDR, but production platforms add kernel-level telemetry (eBPF/ETW) instead of polling, a cloud backend for fleet-wide correlation, ML classifiers, memory scanning, and response actions (kill process, quarantine, isolate host). Natural next steps here: eBPF-based exec hooks, YARA integration, a central alert collector over HTTP, and containment actions.
