import json
from pathlib import Path
from datetime import datetime

INPUT_FILE = Path("soc_ml_engine/outputs/prioritized_incidents.json")
OUTPUT_FILE = Path("soc_ml_engine/outputs/incident_report.json")


def generate_report(incidents):

    report = {
        "generated_at": str(datetime.now()),
        "total_incidents": len(incidents),
        "incidents": []
    }

    for incident in incidents:

        summary = {
            "incident_type": incident.get("incident_type"),
            "severity": incident.get("severity"),
            "priority_level": incident.get("priority_level"),
            "priority_score": incident.get("priority_score"),
            "attack_technique": incident.get("attack_technique"),
            "host": incident.get("host"),
            "source_ip": incident.get("source_ip"),
            "confidence": incident.get("confidence"),
            "reason": incident.get("reason"),
            "evidence": incident.get("evidence", []),

            "recommended_actions": [
                "Investigate suspicious activity",
                "Review endpoint telemetry",
                "Check related network connections",
                "Validate ATT&CK technique behavior",
                "Escalate if malicious activity confirmed"
            ]
        }

        report["incidents"].append(summary)

    return report


def main():

    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        incidents = json.load(f)

    report = generate_report(incidents)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Generated report for {len(incidents)} incidents")


if __name__ == "__main__":
    main()