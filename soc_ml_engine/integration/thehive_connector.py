"""Push ML incident findings to TheHive as alerts or full cases."""

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — reads from environment variables
# ---------------------------------------------------------------------------

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://192.168.56.20:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

REPORT_FILE = Path("soc_ml_engine/outputs/incident_report.json")
PRIORITIZED_FILE = Path("soc_ml_engine/outputs/prioritized_incidents.json")
FINDINGS_FILE = Path("soc_ml_engine/outputs/suspicious_events.json")

SEVERITY_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4}
TLP_MAP = {"critical": 3, "high": 2, "medium": 2, "low": 1}


# ---------------------------------------------------------------------------
# TheHive API helpers
# ---------------------------------------------------------------------------

def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }


def create_alert(incident: dict[str, Any]) -> dict[str, Any] | None:
    """Create a TheHive alert from a single ML incident."""

    severity_label = str(incident.get("severity", "medium")).lower()
    severity = SEVERITY_MAP.get(severity_label, 3)
    tlp = TLP_MAP.get(severity_label, 2)

    source_ref = (
        f"soc-ml-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        f"-{incident.get('host', 'unknown')}"
    )

    alert_payload = {
        "title": f"[SOC ML] {incident.get('incident_type', 'Anomaly Detected')}",
        "description": _build_description(incident),
        "severity": severity,
        "tlp": tlp,
        "type": "soc_ml_anomaly",
        "source": "soc_ml_engine",
        "sourceRef": source_ref,
        "tags": _build_tags(incident),
        "artifacts": _build_observables(incident),
    }

    try:
        response = requests.post(
            f"{THEHIVE_URL}/api/alert",
            headers=_headers(),
            json=alert_payload,
            timeout=15,
            verify=False,
        )
        if response.status_code in (200, 201):
            result = response.json()
            LOGGER.info("Created TheHive alert: %s", result.get("id"))
            return result
        LOGGER.error(
            "TheHive alert creation failed (%s): %s",
            response.status_code,
            response.text[:300],
        )
        return None
    except requests.RequestException as exc:
        LOGGER.error("TheHive connection failed: %s", exc)
        return None


def create_case(incident: dict[str, Any]) -> dict[str, Any] | None:
    """Create a full TheHive case with analyst tasks from a prioritized incident."""

    severity_label = str(incident.get("severity", "medium")).lower()
    severity = SEVERITY_MAP.get(severity_label, 3)
    tlp = TLP_MAP.get(severity_label, 2)
    priority_level = incident.get("priority_level", "P3")

    case_payload = {
        "title": (
            f"[{priority_level}] {incident.get('incident_type', 'ML Anomaly')}"
            f" — {incident.get('host', 'unknown')}"
        ),
        "description": _build_description(incident),
        "severity": severity,
        "tlp": tlp,
        "tags": _build_tags(incident),
        "flag": severity <= 2,
        "tasks": [
            {"title": "Validate ML finding in Splunk", "status": "Waiting", "order": 0},
            {"title": "Review endpoint telemetry (Sysmon)", "status": "Waiting", "order": 1},
            {"title": "Review network telemetry (Suricata)", "status": "Waiting", "order": 2},
            {"title": "Determine if activity is malicious", "status": "Waiting", "order": 3},
            {"title": "Containment / remediation if needed", "status": "Waiting", "order": 4},
            {"title": "Document findings and close case", "status": "Waiting", "order": 5},
        ],
    }

    try:
        response = requests.post(
            f"{THEHIVE_URL}/api/case",
            headers=_headers(),
            json=case_payload,
            timeout=15,
            verify=False,
        )
        if response.status_code in (200, 201):
            result = response.json()
            LOGGER.info("Created TheHive case: %s", result.get("id"))

            # attach observables to the case
            case_id = result.get("id")
            if case_id:
                for observable in _build_observables(incident):
                    try:
                        requests.post(
                            f"{THEHIVE_URL}/api/case/{case_id}/artifact",
                            headers=_headers(),
                            json=observable,
                            timeout=10,
                            verify=False,
                        )
                    except requests.RequestException:
                        pass
            return result
        LOGGER.error(
            "TheHive case creation failed (%s): %s",
            response.status_code,
            response.text[:300],
        )
        return None
    except requests.RequestException as exc:
        LOGGER.error("TheHive connection failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _build_description(incident: dict[str, Any]) -> str:
    lines = [
        f"## {incident.get('incident_type', 'Anomaly Detected')}",
        "",
        f"**Host:** {incident.get('host', 'N/A')}",
        f"**Source IP:** {incident.get('source_ip', 'N/A')}",
        f"**Severity:** {incident.get('severity', 'N/A')}",
        f"**Confidence:** {incident.get('confidence', 'N/A')}",
        f"**Priority:** {incident.get('priority_level', 'N/A')} "
        f"(score: {incident.get('priority_score', 'N/A')})",
        f"**ATT&CK Technique:** {incident.get('attack_technique', 'N/A')}",
        "",
        f"**Reason:** {incident.get('reason', 'N/A')}",
        "",
        "### Evidence",
    ]
    for evidence in incident.get("evidence", []):
        lines.append(f"- {evidence}")

    actions = incident.get("recommended_actions", [])
    if actions:
        lines.append("")
        lines.append("### Recommended Actions")
        for action in actions:
            lines.append(f"- {action}")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by soc_ml_engine*")
    return "\n".join(lines)


def _build_tags(incident: dict[str, Any]) -> list[str]:
    tags = ["soc_ml_engine", "anomaly"]
    severity = str(incident.get("severity", "")).lower()
    if severity:
        tags.append(f"severity:{severity}")
    technique = incident.get("attack_technique")
    if technique:
        tags.append(f"mitre:{technique}")
    incident_type = incident.get("incident_type", "")
    if incident_type:
        tags.append(incident_type.lower().replace(" ", "_"))
    return tags


def _build_observables(incident: dict[str, Any]) -> list[dict[str, Any]]:
    observables: list[dict[str, Any]] = []
    host = incident.get("host")
    if host:
        observables.append({
            "dataType": "hostname",
            "data": host,
            "message": "Affected host from ML anomaly finding",
        })
    source_ip = incident.get("source_ip")
    if source_ip:
        observables.append({
            "dataType": "ip",
            "data": source_ip,
            "message": "Source IP address from ML anomaly finding",
        })
    return observables


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def push_to_thehive(mode: str = "alerts") -> None:
    """Push incidents to TheHive.

    mode='alerts'  — creates lightweight TheHive alerts from incident_report.json
    mode='cases'   — creates full TheHive cases with tasks from prioritized_incidents.json
    """

    if not THEHIVE_API_KEY:
        print("[ERROR] THEHIVE_API_KEY environment variable is not set.")
        print("        Set it with:  $env:THEHIVE_API_KEY = \"<your_key>\"")
        return

    if mode == "cases":
        if not PRIORITIZED_FILE.exists():
            print(f"[ERROR] {PRIORITIZED_FILE} not found.")
            print("        Run the correlation pipeline first:")
            print("          python -m soc_ml_engine.correlation.correlator")
            print("          python -m soc_ml_engine.correlation.prioritizer")
            return
        with open(PRIORITIZED_FILE, "r", encoding="utf-8") as f:
            incidents = json.load(f)
        print(f"[+] Pushing {len(incidents)} incidents as TheHive cases...")
        created = 0
        for incident in incidents:
            result = create_case(incident)
            if result:
                print(f"    [OK] Case: {result.get('title', result.get('id'))}")
                created += 1
            else:
                print(f"    [FAIL] {incident.get('incident_type', 'unknown')}")
        print(f"\n[+] Done — {created}/{len(incidents)} cases created in TheHive")

    else:
        if not REPORT_FILE.exists():
            print(f"[ERROR] {REPORT_FILE} not found.")
            print("        Run the full correlation pipeline first:")
            print("          python -m soc_ml_engine.correlation.correlator")
            print("          python -m soc_ml_engine.correlation.prioritizer")
            print("          python -m soc_ml_engine.correlation.report_generator")
            return
        with open(REPORT_FILE, "r", encoding="utf-8") as f:
            report = json.load(f)
        incidents = report.get("incidents", [])
        print(f"[+] Pushing {len(incidents)} incidents as TheHive alerts...")
        created = 0
        for incident in incidents:
            result = create_alert(incident)
            if result:
                print(f"    [OK] Alert: {result.get('title', result.get('id'))}")
                created += 1
            else:
                print(f"    [FAIL] {incident.get('incident_type', 'unknown')}")
        print(f"\n[+] Done — {created}/{len(incidents)} alerts created in TheHive")


def test_connection() -> None:
    """Quick connectivity check against TheHive API."""

    print(f"[*] Testing connection to {THEHIVE_URL} ...")
    if not THEHIVE_API_KEY:
        print("[ERROR] THEHIVE_API_KEY is not set.")
        return
    try:
        response = requests.get(
            f"{THEHIVE_URL}/api/status",
            headers=_headers(),
            timeout=10,
            verify=False,
        )
        if response.status_code == 200:
            print(f"[OK] TheHive is reachable — status: {response.json()}")
        else:
            print(f"[WARN] TheHive responded with {response.status_code}: {response.text[:200]}")
    except requests.RequestException as exc:
        print(f"[ERROR] Cannot reach TheHive: {exc}")


def main() -> None:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Push SOC ML Engine findings to TheHive"
    )
    parser.add_argument(
        "--mode",
        choices=["alerts", "cases", "test"],
        default="alerts",
        help=(
            "'alerts' — create TheHive alerts from incident report; "
            "'cases' — create full cases with analyst tasks; "
            "'test' — check TheHive connectivity"
        ),
    )
    parser.add_argument(
        "--url",
        help="Override THEHIVE_URL (default: from env or http://192.168.56.20:9000)",
    )
    parser.add_argument(
        "--api-key",
        help="Override THEHIVE_API_KEY (default: from env)",
    )
    args = parser.parse_args()

    global THEHIVE_URL, THEHIVE_API_KEY
    if args.url:
        THEHIVE_URL = args.url
    if args.api_key:
        THEHIVE_API_KEY = args.api_key

    if args.mode == "test":
        test_connection()
    else:
        push_to_thehive(mode=args.mode)


if __name__ == "__main__":
    main()
