"""Alert taxonomy: map MITRE ATT&CK techniques to tactics.

Rules already carry technique IDs (e.g. "T1059"); this module rolls them up
to the tactic level so reports and incidents read as an attack narrative
("Credential Access", "Command and Control") instead of raw technique codes.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List

# Canonical ATT&CK technique -> tactic(s) for the techniques Aegis rules use.
TECHNIQUE_TACTICS: Dict[str, List[str]] = {
    "T1003": ["Credential Access"],                 # OS Credential Dumping
    "T1027": ["Defense Evasion"],                   # Obfuscation
    "T1053": ["Execution", "Persistence", "Privilege Escalation"],  # Scheduled Task
    "T1055": ["Defense Evasion", "Privilege Escalation"],           # Process Injection
    "T1059": ["Execution"],                         # Command and Scripting Interpreter
    "T1070": ["Defense Evasion"],                   # Indicator Removal
    "T1071": ["Command and Control"],               # Application Layer Protocol
    "T1098": ["Persistence", "Privilege Escalation"],               # Account Manipulation
    "T1105": ["Command and Control"],               # Ingress Tool Transfer
    "T1136": ["Persistence"],                       # Create Account
    "T1140": ["Defense Evasion"],                   # Deobfuscate/Decode
    "T1547": ["Persistence", "Privilege Escalation"],               # Autostart
    "T1552": ["Credential Access"],                 # Unsecured Credentials
    "T1556": ["Credential Access", "Defense Evasion", "Persistence"],  # Modify Auth
    "T1571": ["Command and Control"],               # Non-Standard Port
    "T1620": ["Defense Evasion", "Privilege Escalation"],           # Reflective Code Loading
}

# ATT&CK kill-chain ordering, used to sort tactics in output.
TACTIC_ORDER = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
)
_TACTIC_RANK = {t: i for i, t in enumerate(TACTIC_ORDER)}


def tactics_for(techniques: Iterable[str]) -> List[str]:
    """Map technique IDs to their tactics, kill-chain ordered, deduplicated."""
    tactics = {t for tech in techniques for t in TECHNIQUE_TACTICS.get(tech, [])}
    return sorted(tactics, key=lambda t: _TACTIC_RANK.get(t, len(TACTIC_ORDER)))


def classify_alert(alert) -> List[str]:
    """Tactics for one alert (uses its MITRE technique list)."""
    return tactics_for(alert.mitre)


def tactic_summary(alerts: Iterable) -> Counter:
    """Tactic -> alert count across an alert set."""
    summary: Counter = Counter()
    for alert in alerts:
        for tactic in classify_alert(alert):
            summary[tactic] += 1
    return summary
