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
            return re.search(self.value, str(actual), re.IGNORECASE) is not None
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

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        if data.get("severity") not in SEVERITIES:
            raise ValueError(f"rule {data.get('id')}: invalid severity")
        conditions = [Condition(**c) for c in data.get("conditions", [])]
        logic = data.get("logic", "all")
        if logic not in ("all", "any"):
            raise ValueError(f"rule {data.get('id')}: logic must be 'all' or 'any'")
        return cls(
            id=data["id"], name=data["name"], severity=data["severity"],
            event_type=data["event_type"], description=data.get("description", ""),
            conditions=conditions, logic=logic,
            mitre=data.get("mitre", []), enabled=data.get("enabled", True),
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


def load_iocs(path: Path | str) -> Dict[str, set]:
    """Load the IOC store: {"ip": [...], "domain": [...], "sha256": [...]}."""
    path = Path(path)
    if not path.exists():
        return {"ip": set(), "domain": set(), "sha256": set()}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: set(v) for k, v in data.items()}
