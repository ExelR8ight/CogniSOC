"""Push ML findings and correlated incidents to Splunk via HTTP Event Collector.

This script sends both sourcetypes that the SOC Command Center dashboard expects:
  - soc:ml:anomaly   — from suspicious_events.json
  - soc:ml:incident  — from prioritized_incidents.json (enriched with timeline + report data)
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

FINDINGS_FILE = Path("soc_ml_engine/outputs/suspicious_events.json")
PRIORITIZED_FILE = Path("soc_ml_engine/outputs/prioritized_incidents.json")
TIMELINES_FILE = Path("soc_ml_engine/outputs/attack_timelines.json")
REPORT_FILE = Path("soc_ml_engine/outputs/incident_report.json")

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique-to-tactic mapping for enrichment
# ---------------------------------------------------------------------------

TECHNIQUE_TACTIC_MAP = {
    "T1046": "Discovery",
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1057": "Discovery",
    "T1016": "Discovery",
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1047": "Execution",
    "T1112": "Defense Evasion",
    "T1053": "Persistence",
    "T1518": "Discovery",
    "T1033": "Discovery",
    "T1087": "Discovery",
    "T1007": "Discovery",
    "T1110": "Credential Access",
    "T1027": "Defense Evasion",
    "T1218": "Defense Evasion",
    "T1003": "Credential Access",
    "T1048": "Exfiltration",
    "T1204": "Execution",
    "T1498": "Impact",
    "T1566": "Initial Access",
    "T1074": "Collection",
    "T1078": "Persistence",
}

INCIDENT_CATEGORY_MAP = {
    "Reconnaissance Activity": "Network Reconnaissance",
    "Suspicious PowerShell Activity": "Endpoint Execution",
    "Brute Force Attempt": "Credential Attack",
    "Data Exfiltration": "Data Theft",
    "Lateral Movement": "Lateral Movement",
    "Insider Threat": "Insider Threat",
}

# ---------------------------------------------------------------------------
# Enrichment helpers
# ---------------------------------------------------------------------------

def _enrich_incident(incident: dict[str, Any], timelines: list[dict], report_incidents: list[dict]) -> dict[str, Any]:
    """Enrich a prioritized incident with all the fields the Splunk dashboard expects."""

    technique = incident.get("attack_technique", "")
    tactic = TECHNIQUE_TACTIC_MAP.get(technique, "Unknown")
    incident_type = incident.get("incident_type", "Unknown")
    category = INCIDENT_CATEGORY_MAP.get(incident_type, incident_type)

    # Find matching timeline
    host = incident.get("host", "")
    timeline_stage = "Detection"
    for tl in timelines:
        if tl.get("host") == host and tl.get("incident_type") == incident_type:
            events = tl.get("timeline", [])
            if events:
                timeline_stage = "Reconnaissance → Detection → Correlation"

    # Find matching report entry for remediation actions
    remediation_actions = [
        "Investigate suspicious activity",
        "Review endpoint telemetry",
        "Check related network connections",
        "Validate ATT&CK technique behavior",
        "Escalate if malicious activity confirmed",
    ]
    for report_entry in report_incidents:
        if report_entry.get("incident_type") == incident_type and report_entry.get("host") == host:
            remediation_actions = report_entry.get("recommended_actions", remediation_actions)
            break

    SIGMA_MAP = {
        "Reconnaissance Activity": ("SIGMA-1046", "Suspicious Network Reconnaissance (Port Scan)"),
        "Suspicious PowerShell Activity": ("SIGMA-1059", "Suspicious PowerShell Encoded Command Execution"),
        "Brute Force Attempt": ("SIGMA-1110", "Multiple Failed Login Attempts (Brute Force)"),
        "Data Exfiltration": ("SIGMA-1048", "Excessive External Connections with File Creations"),
        "Suspicious LOLBin Execution": ("SIGMA-1218", "Living-off-the-land Binary Proxy Execution"),
        "Malicious Process Execution": ("SIGMA-1050", "High Risk or Extremely Rare Process Execution"),
    }
    sigma_id, sigma_title = SIGMA_MAP.get(incident_type, ("", ""))

    return {
        "incident_type": incident_type,
        "incident_category": category,
        "severity": incident.get("severity", "Medium"),
        "confidence": incident.get("confidence", "Medium"),
        "priority_level": incident.get("priority_level", "P3"),
        "priority_score": incident.get("priority_score", 0),
        "attack_technique": technique,
        "mitre_tactics": [tactic],
        "host": host,
        "source_ip": incident.get("source_ip", ""),
        "reason": incident.get("reason", ""),
        "evidence": incident.get("evidence", []),
        "remediation_actions": remediation_actions,
        "timeline_stage": timeline_stage,
        "sigma_rule_id": sigma_id,
        "sigma_rule_title": sigma_title,
        "thehive_case_id": "",
        "thehive_status": "Open",
        "source": "soc_ml_engine",
    }


# ---------------------------------------------------------------------------
# HEC push
# ---------------------------------------------------------------------------

def push_to_hec(
    hec_url: str,
    hec_token: str,
    events: list[dict[str, Any]],
    sourcetype: str,
    index: str = "main",
) -> tuple[int, int]:
    """Push events to Splunk HEC. Returns (success_count, fail_count)."""

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }

    success = 0
    failed = 0

    for event in events:
        payload = {
            "time": datetime.now(timezone.utc).timestamp(),
            "host": event.get("host") or event.get("source_ip") or "soc_ml_engine",
            "sourcetype": sourcetype,
            "index": index,
            "event": event,
        }

        try:
            response = requests.post(
                hec_url,
                headers=headers,
                json=payload,
                verify=False,
                timeout=10,
            )
            if response.status_code == 200:
                success += 1
            else:
                LOGGER.warning("HEC push failed (%s): %s", response.status_code, response.text[:200])
                failed += 1
        except requests.RequestException as exc:
            LOGGER.warning("HEC push error: %s", exc)
            failed += 1

    return success, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")

    parser = argparse.ArgumentParser(description="Push ML findings and incidents to Splunk HEC")
    parser.add_argument("--hec-url", required=True, help="Splunk HEC URL, e.g. https://192.168.56.20:8088/services/collector")
    parser.add_argument("--hec-token", required=True, help="Splunk HEC token")
    parser.add_argument("--index", default="main", help="Splunk index (default: main)")
    parser.add_argument("--findings-only", action="store_true", help="Only push ML findings (soc:ml:anomaly)")
    parser.add_argument("--incidents-only", action="store_true", help="Only push correlated incidents (soc:ml:incident)")
    args = parser.parse_args()

    push_findings = not args.incidents_only
    push_incidents = not args.findings_only

    # ---- Push ML findings (soc:ml:anomaly) ----
    if push_findings:
        if FINDINGS_FILE.exists():
            with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
                findings = json.load(f)
            print(f"[+] Pushing {len(findings)} ML findings as soc:ml:anomaly ...")
            ok, fail = push_to_hec(args.hec_url, args.hec_token, findings, "soc:ml:anomaly", args.index)
            print(f"    [OK] {ok} pushed, {fail} failed")
        else:
            print(f"[SKIP] {FINDINGS_FILE} not found — run ML detection first")

    # ---- Push correlated incidents (soc:ml:incident) ----
    if push_incidents:
        if PRIORITIZED_FILE.exists():
            with open(PRIORITIZED_FILE, "r", encoding="utf-8") as f:
                prioritized = json.load(f)

            # Load timelines and report for enrichment
            timelines = []
            if TIMELINES_FILE.exists():
                with open(TIMELINES_FILE, "r", encoding="utf-8") as f:
                    timelines = json.load(f)

            report_incidents = []
            if REPORT_FILE.exists():
                with open(REPORT_FILE, "r", encoding="utf-8") as f:
                    report = json.load(f)
                    report_incidents = report.get("incidents", [])

            enriched = [_enrich_incident(inc, timelines, report_incidents) for inc in prioritized]

            print(f"[+] Pushing {len(enriched)} correlated incidents as soc:ml:incident ...")
            ok, fail = push_to_hec(args.hec_url, args.hec_token, enriched, "soc:ml:incident", args.index)
            print(f"    [OK] {ok} pushed, {fail} failed")
        else:
            print(f"[SKIP] {PRIORITIZED_FILE} not found — run correlation pipeline first")

    print("\n[+] Splunk HEC push complete")
    print("    Verify in Splunk: index=main (sourcetype=\"soc:ml:anomaly\" OR sourcetype=\"soc:ml:incident\")")


if __name__ == "__main__":
    main()
