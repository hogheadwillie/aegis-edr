# Aegis EDR

A host-based Endpoint Detection & Response (EDR) tool in Python, modeled on how platforms like CrowdStrike Falcon work: a lightweight agent monitors **processes, network connections, and file integrity**, matches observations against a **behavioral rule engine** mapped to MITRE ATT&CK, produces **severity-scored alerts**, and can take **active response actions** — kill the process, quarantine the file, firewall-block the C2. Every line of executable code in this project is Python — including the web console, which is server-rendered with zero JavaScript.

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
              │  Alert pipeline     │  console + JSONL log, session dedup,
              │  ~/.aegis/alerts.*  │  hash-chained + replicated seal ledger
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  Analytics layer    │  cross-source incident correlation,
              │  (aegis/analytics)  │  behavioral baselining, ATT&CK tactics
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  Active response    │  kill process, quarantine file,
              │  (safe-by-default)  │  firewall-block C2 — dry-run first
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  Web layer (pure    │  server-rendered console
              │  Python, no JS)     │  + bearer-token JSON API
              └─────────────────────┘
```

## Built-in detections (12 rules, MITRE-mapped)

| Rule | Detection | Severity | ATT&CK | Response |
|------|-----------|----------|--------|----------|
| PROC-001 | Execution from temp directory | high | T1059, T1070 | — |
| PROC-002 | Fileless / deleted-binary execution | critical | T1055, T1620 | kill_process |
| PROC-003 | Obfuscated or encoded command line | high | T1027, T1140 | — |
| PROC-004 | Credential store access attempt | high | T1003, T1552 | — |
| PROC-005 | Download-and-execute cradle | medium | T1105, T1059 | — |
| NET-001 | Connection to known-malicious IP (IOC) | critical | T1071 | block_ip |
| NET-002 | Connection on classic C2 port | medium | T1071, T1571 | — |
| NET-003 | Possible reverse shell | high | T1059, T1071 | — |
| NET-004 | Shell listening on network port | critical | T1059, T1571 | kill_process |
| FIM-001 | Sensitive account/auth file changed | critical | T1098, T1136, T1556 | — |
| FIM-002 | New content in startup/persistence location | high | T1547, T1053 | — |
| FIM-003 | Executable written to temp directory | medium | T1070, T1059 | quarantine_file |

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

# summarize the alert log (severity + ATT&CK tactic rollup)
python -m aegis report --severity high

# analytics: correlate alerts into incidents, verify ledger, baseline the host
python -m aegis incidents --window 300
python -m aegis alerts verify                 # tamper check: chain + replicas
python -m aegis alerts recover                # rebuild a lost seal from replicas
python -m aegis baseline learn --cycles 10    # learn the host's normal profile
python -m aegis baseline check                # anomaly? exit code 2

# active response: dry-run by default, --execute to act for real
python -m aegis scan --auto-respond                  # show what WOULD be contained
python -m aegis scan --auto-respond --execute        # contain matching threats now
python -m aegis respond kill 1337 --execute          # manual containment
python -m aegis respond quarantine /tmp/dropper.sh --execute
python -m aegis respond restore cebf25e0             # put a quarantined file back
python -m aegis respond block 203.0.113.66 --execute # iptables DROP (needs root)
python -m aegis respond vault / blocked / log        # inspect state + audit trail

# web dashboard + REST API (localhost only, token-authenticated)
pip install ".[web]"
python -m aegis serve            # http://127.0.0.1:8765
cat ~/.aegis/api_token           # paste into the dashboard login
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
`"logic": "all"` (default, AND) or `"any"` (OR). Regex conditions are screened
for catastrophic-backtracking shapes (nested quantifiers) at load and capped at
1 s evaluation time at runtime — a hostile rule can't hang the agent.

Add `"response": "kill_process" | "quarantine_file" | "block_ip"` to have the
agent contain the threat when the rule fires (only with `--auto-respond`;
dry-run unless `--execute` is also given).

## Active response

CrowdStrike-style containment, safe by default — **nothing executes without
`--execute`**, and every action (executed, dry-run, or refused) is appended to
`~/.aegis/response.jsonl` (0600):

| Action | What it does | Guard rails |
|--------|--------------|-------------|
| `kill_process` | SIGTERM, then SIGKILL | refuses PID 0/1, itself, its own ancestors, and system daemons (systemd, sshd, …) |
| `quarantine_file` | moves the file into a 0700 vault as `sha256`, chmod 000, manifest for `restore` | refuses symlinks, system trees (/usr, /etc, /bin…), >512 MB |
| `block_ip` | `iptables` DROP in + out | refuses loopback/multicast/unspecified; `unblock` reverses it |

Each (action, target) fires at most once per agent run, so a watch loop won't
hammer the same containment. Rules opt in individually via the `response` key —
auto-response never acts on rules that don't declare one. All responder inputs
are scrubbed: IPs are sanitized to printable ASCII before parsing or logging,
and quarantine restore ids must be hex SHA-256 prefixes — a crafted id can't
traverse paths or crash the audit trail.

## Analytics layer

Four capabilities inspired — **as architectural metaphor only** — by
holographic/distributed information models (see the note at the bottom; no
quantum claims are made or needed):

| Inspiration | Feature | How it works |
|-------------|---------|--------------|
| Holographic storage — every fragment holds the whole | **Tamper-evident seal ledger** | Every alert is appended to a hash-chained log (`~/.aegis/sealed/`, 0600 in 0700) mirrored to two replicas. `alerts verify` detects edits, deletions, and reordering; `alerts recover` rebuilds a lost seal from the replicas. Appends are serialized by a thread lock + `fcntl.flock`, so concurrent threads/processes can't break the chain |
| Non-local correlation | **Incident correlation** | `incidents` fuses process/network/FIM alerts that share a PID, remote IP, or path within a time window into one incident with max severity and combined tactics — one intrusion reads as one story, not nine alerts |
| Resonance against a stored pattern | **Behavioral baselining** | `baseline learn` profiles the host's normal process/network metrics; `baseline check` scores fresh samples with per-metric z-scores and raises `ANOM-001` when the host diverges — catching what no rule matches |
| Ontology of states | **ATT&CK tactic taxonomy** | Technique IDs roll up to kill-chain-ordered tactics in `report` and incidents |

**Honest ledger limitation:** the seal proves tampering by anyone who can't
rewrite *all* copies consistently; a root attacker who rewrites every replica
can still forge history. Forward-secure integrity requires shipping seals
off-host (syslog-ng, immutable object storage) — noted as a next step.

## Running the tests

```bash
pip install pytest httpx
python -m pytest tests/ -v   # 153 tests (core + web + multi-user + response + analytics + stress)
```

The suite includes an **adversarial stress layer** (`tests/test_stress.py`)
that attacks every input boundary — fuzzed rule files, malformed IOC stores,
corrupt alert logs, ledger tampering/reordering/truncation, hostile baseline
stats, manifest injection, 10k-alert correlation load, and 8-thread ×
60-process concurrency races on the seal ledger and IOC store. Hardening that
came out of it:

- **ReDoS defense**: nested-quantifier regexes rejected at rule load; a 1 s
  `setitimer` timeout caps any pattern that slips through at runtime
- **Ledger concurrency**: process-wide lock + `fcntl.flock` on the primary
  seal with tail re-read under the lock — 200 concurrent appends verify clean
- **Corruption tolerance**: a single bad line in the alert log, quarantine
  manifest, or seal never blinds the reader — good records survive
- **Schema strictness**: rules reject non-dict items, unknown condition
  fields, non-list `mitre`/`conditions`; IOC store capped at 100k values / 5 MB
  and requires category→list-of-strings
- **Input scrubbing**: `block_ip`/`unblock_ip`/`restore_file` sanitize to
  printable ASCII (surrogates/NULs can't crash the audit write); quarantine
  restore ids must be hex SHA-256 prefixes
- **Atomic IOC writes**: read-modify-write under `flock` + temp-file rename —
  no lost updates under a 60-process race

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

## Managing accounts & the API token

```bash
python -m aegis user add alice --role admin           # generates a strong password
python -m aegis user add bob --role analyst --password '...'
python -m aegis user passwd alice                     # interactive change
python -m aegis user list
python -m aegis user remove bob                       # last admin is protected

python -m aegis token show                            # print the JSON API token
python -m aegis token rotate                          # new token, old one dies instantly
```

## Project layout

```
aegis/
├── aegis/
│   ├── agent.py              # orchestration, watch loop, dedup
│   ├── alerts.py             # alert model, JSONL sink (+ sealed ledger), reporting loader
│   ├── analytics/
│   │   ├── correlate.py      # cross-source incident correlation (entity union-find)
│   │   ├── baseline.py       # behavioral baseline learning + z-score anomaly alerts
│   │   ├── ledger.py         # hash-chained, replicated, tamper-evident alert seal
│   │   └── taxonomy.py       # MITRE ATT&CK technique -> tactic rollup
│   ├── cli.py                # scan / watch / fim / ioc / report / respond / incidents /
│   │                         # alerts / baseline / serve / user / token
│   ├── detection/engine.py   # rule matching + IOC store (ReDoS-guarded)
│   ├── monitors/
│   │   ├── process.py        # process enumeration (incl. deleted-binary check)
│   │   ├── network.py        # connection/listener snapshot
│   │   └── fim.py            # SHA-256 baselines and diffing
│   ├── response/actions.py   # active response: kill / quarantine / block + audit
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
├── tests/test_response.py
├── tests/test_analytics.py
├── tests/test_stress.py
└── pyproject.toml
```

## Web console & API security — pure Python, zero JavaScript

The web layer (`aegis serve`) is a fully server-rendered application: **every
line of executable code in this project is Python**. The dashboard is Jinja2
HTML rendered by FastAPI — there is no JavaScript anywhere in the stack.

**Browser UI (server-rendered)**
- **Multi-user accounts** with quantum-resistant password hashing: Argon2id (RFC 9106, OWASP parameters — 64 MiB, 3 iterations). Argon2id's security is unaffected by Shor's algorithm and Grover's only halves symmetric strength, so brute force stays infeasible for classical *and* quantum adversaries. Only hashes are ever stored (0600 file).
- Password policy: 12–128 chars, offline common-password blocklist, and a full Argon2id verification runs even for nonexistent usernames — response timing can't enumerate accounts.
- Roles: `admin` (manage users, view audit log) and `analyst` (console only). Single-token mode remains until the first account is created (`aegis user add <name> --role admin`); the last admin cannot be removed.
- **Per-account lockout** (5 failures → 10 min) stops distributed password guessing that per-IP lockouts alone can't; lockouts are audited.
- Audit trail: logins, failed logins, lockouts, scans, password changes, and user/IOC changes appended to `~/.aegis/audit.jsonl` (0600) — with client IP on every event.
- Self-service password change in the console; changing a password **revokes every other session** of the account, and removing a user kills their sessions instantly.
- Sessions: opaque cookie (`HttpOnly`, `SameSite=Strict`, 12 h sliding expiry, `Secure` + `__Host-` prefix with `--secure-cookies`), per-session CSRF token on every form POST, max 5 concurrent sessions per user (oldest evicted).
- Jinja2 autoescaping makes all rendered alert/rule/IOC data XSS-safe by default; Post/Redirect/Get throughout.

**JSON API (`/api/*`, for scripts)**
- Bearer-token auth on every route, 256-bit token generated on first run and stored `0600` in a `0700` directory; `aegis token rotate` invalidates it on demand
- Constant-time token comparison (`hmac.compare_digest`) — no timing oracle

**Edge guards (run before any route)**
- Origin/Referer enforcement: cross-site POSTs are 403'd at the edge — second CSRF layer behind the token check
- Request body cap (64 KiB → 413) before any parsing
- Per-IP sliding-window rate limiting (120 req/min global; 10 req/min on `/login` and scans) and brute-force lockout (5 failures → 5 min) on both surfaces

**Shared defenses**
- Security headers on every response (including edge rejections): strict CSP (`default-src 'none'`, `form-action 'self'`, `frame-ancestors 'none'`, `base-uri 'none'`), `nosniff`, `DENY` framing, `no-store`, `no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Server` header stripped
- No CORS (same-origin only), no `docs`/`openapi.json` exposed, validated inputs, path-traversal guards on static files and FIM directories
- Unhandled exceptions return a generic 500 and are written to the audit log — internals never leak
- Binds to `127.0.0.1` by default; refuses non-loopback binds without `--allow-remote` (put it behind a TLS-terminating proxy for remote use)

**Core hardening (applies to the CLI too)**
- Alert log, IOC store, FIM baselines, and API token are written `0600` inside `0700` directories
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

## Honest limitations vs. a real EDR

Aegis demonstrates the *architecture* of an EDR, but production platforms add kernel-level telemetry (eBPF/ETW) instead of polling, a cloud backend for fleet-wide correlation, ML classifiers, memory scanning, and full host isolation (Aegis blocks per-IP only). Natural next steps here: eBPF-based exec hooks, YARA integration, off-host seal shipping for forward-secure logs, and a central alert collector over HTTP.

---

*Provenance note: the analytics layer's design metaphors (distributed/holographic storage, non-local correlation, resonance matching, state ontology) were adapted from a consciousness-studies paper the author found interesting (Valverde et al., NeuroQuantology 2022). That paper's physics claims are scientifically contested and play **no** role in the implementation — every mechanism above is ordinary, verifiable software engineering.*
