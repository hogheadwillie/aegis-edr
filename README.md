# Aegis EDR

A host-based Endpoint Detection & Response (EDR) tool in Python, modeled on how platforms like CrowdStrike Falcon work: a lightweight agent monitors **processes, network connections, and file integrity**, matches observations against a **behavioral rule engine** mapped to MITRE ATT&CK, and produces **severity-scored alerts**.

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
pip install pytest
python -m pytest tests/ -v   # 16 tests
```

## Project layout

```
aegis/
├── aegis/
│   ├── agent.py              # orchestration, watch loop, dedup
│   ├── alerts.py             # alert model, JSONL sink, reporting loader
│   ├── cli.py                # scan / watch / fim / ioc / report
│   ├── detection/engine.py   # rule matching + IOC store
│   ├── monitors/
│   │   ├── process.py        # process enumeration (incl. deleted-binary check)
│   │   ├── network.py        # connection/listener snapshot
│   │   └── fim.py            # SHA-256 baselines and diffing
│   └── rules/default_rules.json
├── tests/test_aegis.py
└── pyproject.toml
```

## Honest limitations vs. a real EDR

Aegis demonstrates the *architecture* of an EDR, but production platforms add kernel-level telemetry (eBPF/ETW) instead of polling, a cloud backend for fleet-wide correlation, ML classifiers, memory scanning, and response actions (kill process, quarantine, isolate host). Natural next steps here: eBPF-based exec hooks, YARA integration, a central alert collector over HTTP, and containment actions.
