"""Rule-based detection engine.

Rules are JSON documents. Each rule has a list of conditions; a condition
checks one event field with an operator. Conditions combine with the rule's
logic ("all" = AND, default, or "any" = OR). Field names support dotted
paths into nested event dicts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..alerts import Alert, SEVERITIES
from ..response.actions import VALID_RESPONSES

# -- ReDoS defense -----------------------------------------------------------
MAX_REGEX_LEN = 500
# Patterns that historically explode: nested quantifiers like (a+)+, (x|x)*$…
_DANGEROUS_REGEX = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*?]")
_REGEX_TIMEOUT = 1.0  # seconds; enforced via signal on Unix


def _check_regex(pattern: str) -> None:
    if len(pattern) > MAX_REGEX_LEN:
        raise ValueError(f"regex too long ({len(pattern)} > {MAX_REGEX_LEN})")
    if _DANGEROUS_REGEX.search(pattern):
        raise ValueError("regex rejected: nested quantifiers (ReDoS risk)")
    re.compile(pattern)  # syntax check


def _timed_search(pattern: str, text: str) -> bool:
    """re.search with a hard timeout so a bad pattern can't hang the agent."""
    import signal

    def _boom(signum, frame):
        raise TimeoutError("regex evaluation exceeded time limit")

    if hasattr(signal, "SIGALRM"):
        old = signal.signal(signal.SIGALRM, _boom)
        signal.setitimer(signal.ITIMER_REAL, _REGEX_TIMEOUT)
        try:
            return re.search(pattern, text, re.IGNORECASE) is not None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)
    return re.search(pattern, text, re.IGNORECASE) is not None


@dataclass
class Condition:
    field: str
    op: str
    value: Any = None

    def matches(self, event: dict, iocs: Dict[str, set]) -> bool:
        actual = _resolve(event, self.field)
        if self.op == "exists":
            return actual is not None
        if actual is None:
            return False
        if self.op == "eq":
            return actual == self.value
        if self.op == "ne":
            return actual != self.value
        if self.op == "gt":
            return actual > self.value
        if self.op == "lt":
            return actual < self.value
        if self.op == "in":
            return actual in self.value
        if self.op == "contains":        # case-insensitive substring
            return str(self.value).lower() in str(actual).lower()
        if self.op == "contains_any":    # any of the substrings
            return any(str(v).lower() in str(actual).lower() for v in self.value)
        if self.op == "startswith":
            return str(actual).lower().startswith(str(self.value).lower())
        if self.op == "endswith":
            return str(actual).lower().endswith(str(self.value).lower())
        if self.op == "regex":
            return _timed_search(str(self.value), str(actual))
        if self.op == "in_ioc":          # value names an IOC category, e.g. "ip"
            return str(actual) in iocs.get(self.value, set())
        raise ValueError(f"unknown operator {self.op!r}")


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    event_type: str
    description: str
    conditions: List[Condition] = field(default_factory=list)
    logic: str = "all"
    mitre: List[str] = field(default_factory=list)
    enabled: bool = True
    response: Optional[str] = None  # optional containment action on match

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        if not isinstance(data, dict):
            raise ValueError("rule must be a JSON object")
        if data.get("severity") not in SEVERITIES:
            raise ValueError(f"rule {data.get('id')}: invalid severity")
        raw_conditions = data.get("conditions", [])
        if not isinstance(raw_conditions, list):
            raise ValueError(f"rule {data.get('id')}: conditions must be a list")
        conditions = []
        for c in raw_conditions:
            if not isinstance(c, dict) or set(c) - {"field", "op", "value"}:
                raise ValueError(f"rule {data.get('id')}: bad condition {c!r}")
            if c.get("op") == "regex":
                _check_regex(str(c.get("value", "")))
            conditions.append(Condition(**c))
        logic = data.get("logic", "all")
        if logic not in ("all", "any"):
            raise ValueError(f"rule {data.get('id')}: logic must be 'all' or 'any'")
        mitre = data.get("mitre", [])
        if not isinstance(mitre, list) or not all(isinstance(t, str) for t in mitre):
            raise ValueError(f"rule {data.get('id')}: mitre must be a list of strings")
        response = data.get("response")
        if response is not None and response not in VALID_RESPONSES:
            raise ValueError(
                f"rule {data.get('id')}: response must be one of {VALID_RESPONSES}")
        return cls(
            id=str(data["id"]), name=str(data["name"]), severity=data["severity"],
            event_type=str(data["event_type"]), description=str(data.get("description", "")),
            conditions=conditions, logic=logic,
            mitre=mitre, enabled=bool(data.get("enabled", True)),
            response=response,
        )

    def matches(self, event: dict, iocs: Dict[str, set]) -> bool:
        if event.get("type") != self.event_type:
            return False
        results = [c.matches(event, iocs) for c in self.conditions]
        return all(results) if self.logic == "all" else any(results)


def _resolve(event: dict, dotted: str) -> Any:
    node: Any = event
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


class DetectionEngine:
    """Matches event dicts against a rule set and an IOC store."""

    def __init__(self, rules: Iterable[Rule], iocs: Optional[Dict[str, set]] = None,
                 host: str = "") -> None:
        self.rules = [r for r in rules if r.enabled]
        self.iocs = {k: set(v) for k, v in (iocs or {}).items()}
        self.host = host

    def evaluate(self, event: dict) -> List[Alert]:
        alerts = []
        for rule in self.rules:
            if rule.matches(event, self.iocs):
                alerts.append(Alert(
                    rule_id=rule.id, name=rule.name, severity=rule.severity,
                    description=rule.description, event_type=rule.event_type,
                    event=event, mitre=rule.mitre, host=self.host,
                ))
        return alerts

    def evaluate_all(self, events: Iterable[dict]) -> List[Alert]:
        out: List[Alert] = []
        for event in events:
            out.extend(self.evaluate(event))
        return out


MAX_RULE_FILE_BYTES = 5 * 1024 * 1024   # refuse absurdly large rule files
MAX_RULES = 10_000


def load_rules(path: Path | str) -> List[Rule]:
    """Load rules from a JSON file or a directory of JSON files."""
    path = Path(path)
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    rules: List[Rule] = []
    for f in files:
        if f.stat().st_size > MAX_RULE_FILE_BYTES:
            raise ValueError(f"rule file {f} exceeds {MAX_RULE_FILE_BYTES} bytes")
        data = json.loads(f.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else [data]
        rules.extend(Rule.from_dict(item) for item in items)
    if len(rules) > MAX_RULES:
        raise ValueError(f"too many rules ({len(rules)} > {MAX_RULES})")
    return rules


MAX_IOC_FILE_BYTES = 5 * 1024 * 1024
MAX_IOC_VALUES = 100_000


def load_iocs(path: Path | str) -> Dict[str, set]:
    """Load the IOC store: {"ip": [...], "domain": [...], "sha256": [...]}."""
    path = Path(path)
    if not path.exists():
        return {"ip": set(), "domain": set(), "sha256": set()}
    if path.stat().st_size > MAX_IOC_FILE_BYTES:
        raise ValueError(f"IOC file {path} exceeds {MAX_IOC_FILE_BYTES} bytes")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("IOC file must be a JSON object of category -> list")
    iocs: Dict[str, set] = {}
    total = 0
    for category, values in data.items():
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError(f"IOC category {category!r} must be a list of strings")
        total += len(values)
        if total > MAX_IOC_VALUES:
            raise ValueError(f"too many IOC values ({total} > {MAX_IOC_VALUES})")
        iocs[str(category)] = set(values)
    return iocs
