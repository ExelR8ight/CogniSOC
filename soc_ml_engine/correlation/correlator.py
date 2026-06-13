import json
from pathlib import Path

INPUT_FILE = Path("soc_ml_engine/outputs/suspicious_events.json")
OUTPUT_FILE = Path("soc_ml_engine/outputs/correlated_incidents.json")


def correlate_incidents(findings):

    incidents = []

    for finding in findings:

        features = finding.get("features", {})

        unique_dest_ports = int(features.get("unique_dest_ports", 0))
        suricata_alert_count = int(features.get("suricata_alert_count", 0))
        powershell_count = int(features.get("powershell_count", 0))

        severity = str(
            finding.get("severity", "")
        ).strip().lower()

        #
        # RULE 1 — Reconnaissance Correlation
        #

        if (
            unique_dest_ports > 100
            and suricata_alert_count > 1
            and severity in ["critical", "high"]
        ):

            incident = {
                "incident_type": "Reconnaissance Activity",
                "severity": "Critical",
                "confidence": "High",
                "attack_technique": "T1046",
                "host": finding.get("host"),
                "source_ip": finding.get("source_ip"),
                "reason": "Correlated network scanning behavior detected",
                "evidence": [
                    f"{unique_dest_ports} unique destination ports",
                    f"{suricata_alert_count} Suricata alerts",
                    f"{features.get('connection_count', 0)} network connections"
                ]
            }

            incidents.append(incident)

        #
        # RULE 2 — Suspicious PowerShell Activity
        #
        if powershell_count > 10 and severity in ["critical", "high", "medium"]:
            incident = {
                "incident_type": "Suspicious PowerShell Activity",
                "severity": "High",
                "confidence": "Medium",
                "attack_technique": "T1059.001",
                "host": finding.get("host"),
                "source_ip": finding.get("source_ip"),
                "reason": "High PowerShell execution frequency with anomalous behavior",
                "evidence": [
                    f"{powershell_count} PowerShell executions",
                    f"Anomaly severity: {severity}"
                ]
            }
            incidents.append(incident)

        #
        # RULE 3 — Brute Force Attempt
        #
        login_failure_count = int(features.get("login_failure_count", 0))
        if login_failure_count > 5 and severity in ["critical", "high", "medium"]:
            incident = {
                "incident_type": "Brute Force Attempt",
                "severity": "High",
                "confidence": "High",
                "attack_technique": "T1110",
                "host": finding.get("host"),
                "source_ip": finding.get("source_ip"),
                "reason": "Multiple authentication failures detected indicating brute force",
                "evidence": [
                    f"{login_failure_count} Failed logins",
                    f"Anomaly severity: {severity}"
                ]
            }
            incidents.append(incident)

        #
        # RULE 4 — Data Exfiltration
        #
        external_connection_count = int(features.get("external_connection_count", 0))
        file_create_count = int(features.get("file_create_count", 0))
        if external_connection_count > 5 and file_create_count > 10 and severity in ["critical", "high"]:
            incident = {
                "incident_type": "Data Exfiltration",
                "severity": "Critical",
                "confidence": "Medium",
                "attack_technique": "T1048",
                "host": finding.get("host"),
                "source_ip": finding.get("source_ip"),
                "reason": "High file creation coupled with excessive external connections",
                "evidence": [
                    f"{file_create_count} File creations",
                    f"{external_connection_count} External connections"
                ]
            }
            incidents.append(incident)

        #
        # RULE 5 — Suspicious LOLBin Execution
        #
        lolbin_count = int(features.get("lolbin_count", 0))
        encoded_command_count = int(features.get("encoded_command_count", 0))
        if lolbin_count > 0 or encoded_command_count > 0:
            incident = {
                "incident_type": "Suspicious LOLBin Execution",
                "severity": "High",
                "confidence": "Medium",
                "attack_technique": "T1218",
                "host": finding.get("host"),
                "source_ip": finding.get("source_ip"),
                "reason": "Living-off-the-land binaries or encoded commands detected",
                "evidence": [
                    f"{lolbin_count} LOLBin executions",
                    f"{encoded_command_count} Encoded commands"
                ]
            }
            incidents.append(incident)

        #
        # RULE 6 — Malicious Process Execution
        #
        high_risk_process_count = int(features.get("high_risk_process_count", 0))
        rare_process_count = int(features.get("rare_process_count", 0))
        if high_risk_process_count > 0 or (rare_process_count > 2 and severity in ["critical", "high"]):
            incident = {
                "incident_type": "Malicious Process Execution",
                "severity": "High",
                "confidence": "Medium",
                "attack_technique": "T1059",
                "host": finding.get("host"),
                "source_ip": finding.get("source_ip"),
                "reason": "Execution of high-risk or extremely rare processes",
                "evidence": [
                    f"{high_risk_process_count} High-risk processes",
                    f"{rare_process_count} Rare processes"
                ]
            }
            incidents.append(incident)

    return incidents


from soc_ml_engine.correlation.incident_classifier import classify_all

def main():

    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        findings = json.load(f)

    print(f"[+] Loaded {len(findings)} findings")

    incidents = correlate_incidents(findings)
    
    # [NEW] Integrate the incident classifier to map categories (Malware, Phishing, etc.)
    incidents = classify_all(incidents)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=4)

    print(f"\n[+] Generated {len(incidents)} correlated incidents (Categorized)")
    print(f"[+] Output written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()