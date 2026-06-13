import json
from pathlib import Path

INCIDENT_FILE = Path("soc_ml_engine/outputs/correlated_incidents.json")
FINDINGS_FILE = Path("soc_ml_engine/outputs/suspicious_events.json")
OUTPUT_FILE = Path("soc_ml_engine/outputs/attack_timelines.json")


def build_timelines(incidents, findings):

    timelines = []

    for incident in incidents:

        host = incident.get("host")

        matching_events = []

        for finding in findings:

            if finding.get("host") == host:

                matching_events.append({
                    "timestamp": finding.get("timestamp"),
                    "event_type": finding.get("event_type"),
                    "severity": finding.get("severity"),
                    "reason": finding.get("reason")
                })

        matching_events = sorted(
            matching_events,
            key=lambda x: x.get("timestamp", "")
        )

        timeline = {
            "incident_type": incident.get("incident_type"),
            "host": host,
            "severity": incident.get("severity"),
            "attack_technique": incident.get("attack_technique"),
            "timeline": matching_events
        }

        timelines.append(timeline)

    return timelines


def main():

    if not INCIDENT_FILE.exists():
        print(f"[ERROR] Input file not found: {INCIDENT_FILE}")
        return
    if not FINDINGS_FILE.exists():
        print(f"[ERROR] Input file not found: {FINDINGS_FILE}")
        return

    with open(INCIDENT_FILE, "r", encoding="utf-8") as f:
        incidents = json.load(f)

    with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
        findings = json.load(f)

    timelines = build_timelines(incidents, findings)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(timelines, f, indent=4)

    print(f"[+] Generated {len(timelines)} attack timelines")


if __name__ == "__main__":
    main()