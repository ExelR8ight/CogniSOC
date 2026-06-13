import json
from pathlib import Path

INPUT_FILE = Path("soc_ml_engine/outputs/correlated_incidents.json")
OUTPUT_FILE = Path("soc_ml_engine/outputs/prioritized_incidents.json")


SEVERITY_SCORES = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25
}

CONFIDENCE_SCORES = {
    "high": 30,
    "medium": 20,
    "low": 10
}


def calculate_priority(incident):

    score = 0

    severity = incident.get("severity", "").lower()
    confidence = incident.get("confidence", "").lower()

    score += SEVERITY_SCORES.get(severity, 0)
    score += CONFIDENCE_SCORES.get(confidence, 0)

    evidence_count = len(incident.get("evidence", []))
    score += evidence_count * 5

    attack_technique = incident.get("attack_technique")

    if attack_technique:
        score += 15

    return min(score, 100)


def prioritize_incidents(incidents):

    prioritized = []

    for incident in incidents:

        priority_score = calculate_priority(incident)

        incident["priority_score"] = priority_score

        if priority_score >= 90:
            incident["priority_level"] = "P1"
        elif priority_score >= 75:
            incident["priority_level"] = "P2"
        elif priority_score >= 50:
            incident["priority_level"] = "P3"
        else:
            incident["priority_level"] = "P4"

        prioritized.append(incident)

    prioritized = sorted(
        prioritized,
        key=lambda x: x["priority_score"],
        reverse=True
    )

    return prioritized


def main():

    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        incidents = json.load(f)

    prioritized = prioritize_incidents(incidents)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(prioritized, f, indent=4)

    print(f"[+] Prioritized {len(prioritized)} incidents")


if __name__ == "__main__":
    main()