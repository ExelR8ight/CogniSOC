"""Local validation harness using bundled sample telemetry."""

from __future__ import annotations

from pathlib import Path

from soc_ml_engine.models.anomaly_model import BehavioralAnomalyModel, write_findings, write_splunk_hec_events
from soc_ml_engine.processing.features import (
    build_feature_frame,
    derive_baseline_profile,
    load_json_events,
    parse_splunk_events,
)


ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "soc_ml_engine" / "tests" / "sample_telemetry.jsonl"
MODEL_PATH = ROOT / "soc_ml_engine" / "outputs" / "validation_model.pkl"
FINDINGS_PATH = ROOT / "soc_ml_engine" / "outputs" / "validation_findings.json"
HEC_PATH = ROOT / "soc_ml_engine" / "outputs" / "validation_splunk_hec.ndjson"


def main() -> int:
    records = load_json_events(SAMPLE)
    baseline_records = [record for record in records if record.get("sample_label") == "baseline"]

    baseline_events = parse_splunk_events(baseline_records)
    baseline_profile = derive_baseline_profile(baseline_events)
    baseline_features = build_feature_frame(baseline_events, window_minutes=15, baseline_profile=baseline_profile)

    model = BehavioralAnomalyModel(contamination=0.05)
    model.train(baseline_features, baseline_profile)
    model.save(MODEL_PATH)

    detection_events = parse_splunk_events(records)
    detection_features = build_feature_frame(detection_events, window_minutes=15, baseline_profile=model.baseline_profile)
    scored = model.score(detection_features)
    findings = model.suspicious_findings(scored, min_score=90.0)

    write_findings(FINDINGS_PATH, findings)
    write_splunk_hec_events(HEC_PATH, findings)

    if not findings:
        raise SystemExit("Expected at least one suspicious finding from sample telemetry")

    print(f"baseline_rows={len(baseline_features)} detection_rows={len(detection_features)} findings={len(findings)}")
    print(f"model={MODEL_PATH}")
    print(f"findings={FINDINGS_PATH}")
    print(f"splunk_hec={HEC_PATH}")
    print(f"top_reason={findings[0]['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
