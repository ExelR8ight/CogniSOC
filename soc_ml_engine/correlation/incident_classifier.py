"""Incident type classifier for high-level categorization.

Maps specific detection incident types (e.g. "Encoded PowerShell Execution")
into the 6 enterprise categories from the project brief:

    1. Malware
    2. Phishing
    3. DDoS
    4. Insider Threat
    5. Brute Force
    6. Data Breach

Each correlated incident gets an ``incident_category`` field added for
dashboard filtering, reporting, and SOC analyst workflows.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── Category mapping rules ──────────────────────────────────────────────────
# Maps keywords found in incident_type, attack_technique, or sigma rule fields
# to one of the 6 project categories.

CATEGORY_RULES: list[dict[str, Any]] = [
    # --- Malware ---
    {
        "category": "Malware",
        "match_incident_type": ["malware", "lolbin", "defense evasion", "process chain"],
        "match_technique": ["T1204", "T1547", "T1218", "T1055", "T1027"],
    },
    # --- Phishing ---
    {
        "category": "Phishing",
        "match_incident_type": ["phishing", "document execution", "spearphishing"],
        "match_technique": ["T1566", "T1566.001", "T1566.002"],
    },
    # --- DDoS ---
    {
        "category": "DDoS",
        "match_incident_type": ["ddos", "denial of service", "network flood"],
        "match_technique": ["T1498", "T1499"],
    },
    # --- Insider Threat ---
    {
        "category": "Insider Threat",
        "match_incident_type": ["insider", "unusual access", "data staged"],
        "match_technique": ["T1074", "T1078"],
    },
    # --- Brute Force ---
    {
        "category": "Brute Force",
        "match_incident_type": ["brute force", "authentication attack", "credential spray"],
        "match_technique": ["T1110", "T1110.001", "T1110.002", "T1110.003"],
    },
    # --- Data Breach ---
    {
        "category": "Data Breach",
        "match_incident_type": ["exfiltration", "data breach", "credential dump", "credential access"],
        "match_technique": ["T1048", "T1048.003", "T1003", "T1003.001", "T1003.002"],
    },
]

# Fallback: if none of the above match, classify by technique tactic
TACTIC_TO_CATEGORY: dict[str, str] = {
    "Initial Access": "Phishing",
    "Execution": "Malware",
    "Persistence": "Malware",
    "Privilege Escalation": "Malware",
    "Defense Evasion": "Malware",
    "Credential Access": "Brute Force",
    "Discovery": "Reconnaissance",
    "Lateral Movement": "Data Breach",
    "Collection": "Insider Threat",
    "Command and Control": "Malware",
    "Exfiltration": "Data Breach",
    "Impact": "DDoS",
}


def classify_incident(incident: dict[str, Any]) -> str:
    """Classify a single incident into one of the 6 project categories.

    Checks (in priority order):
    1. Explicit ``incident_category`` field from Sigma rule
    2. Pattern match on ``incident_type``
    3. Pattern match on ``attack_technique``
    4. Fallback via MITRE tactic mapping
    5. Default: "Unclassified"
    """

    # 1. Check if Sigma rule already set a category
    explicit = incident.get("incident_category", "")
    if explicit:
        return explicit

    inc_type = str(incident.get("incident_type", "")).lower()
    technique = str(incident.get("attack_technique", ""))
    techniques = incident.get("mitre_techniques", [])
    all_techniques = [technique] + (techniques if isinstance(techniques, list) else [])
    tactics = incident.get("mitre_tactics", [])

    # 2 & 3. Pattern match against category rules
    for rule in CATEGORY_RULES:
        # Check incident_type keywords
        for keyword in rule.get("match_incident_type", []):
            if keyword in inc_type:
                return rule["category"]

        # Check technique IDs
        for tech in all_techniques:
            if tech in rule.get("match_technique", []):
                return rule["category"]

    # 4. Fallback: tactic-based classification
    for tactic in tactics:
        if tactic in TACTIC_TO_CATEGORY:
            return TACTIC_TO_CATEGORY[tactic]

    # 5. Last resort: infer from incident type keywords
    if "recon" in inc_type or "scan" in inc_type or "discovery" in inc_type:
        return "Reconnaissance"
    if "powershell" in inc_type or "execution" in inc_type:
        return "Malware"
    if "lateral" in inc_type:
        return "Data Breach"

    return "Unclassified"


def classify_all(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add ``incident_category`` to all incidents.

    Returns the same list with each incident enriched with the category field.
    Does NOT modify the original dicts — returns new copies.
    """

    classified: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}

    for incident in incidents:
        enriched = dict(incident)
        category = classify_incident(incident)
        enriched["incident_category"] = category
        classified.append(enriched)

        category_counts[category] = category_counts.get(category, 0) + 1

    logger.info(
        "Incident classification: %s",
        ", ".join(f"{cat}={count}" for cat, count in sorted(category_counts.items())),
    )
    return classified


def category_summary(incidents: list[dict[str, Any]]) -> dict[str, int]:
    """Return a count of incidents per category."""

    counts: dict[str, int] = {
        "Malware": 0,
        "Phishing": 0,
        "DDoS": 0,
        "Insider Threat": 0,
        "Brute Force": 0,
        "Data Breach": 0,
    }
    for inc in incidents:
        cat = inc.get("incident_category", classify_incident(inc))
        counts[cat] = counts.get(cat, 0) + 1
    return counts
