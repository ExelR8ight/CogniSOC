"""
Expanded Evaluation Script to get per-technique recall and other metrics.
"""

import json
import pandas as pd
from pathlib import Path
from evaluation.synthetic_telemetry import generate_full_dataset
from evaluation.rules_only_detector import RulesOnlyDetector
from evaluation.ablation_runner import run_ablation
from soc_ml_engine.processing.features import parse_splunk_events, build_feature_frame, derive_baseline_profile
from soc_ml_engine.models.anomaly_model import BehavioralAnomalyModel
from soc_ml_engine.correlation.correlator import correlate_incidents
from soc_ml_engine.correlation.prioritizer import prioritize_incidents

def run_expanded_evaluation():
    print("[*] Generating dataset...")
    all_events, window_labels = generate_full_dataset(benign_windows=40, attack_repetitions=3)
    
    events_df = parse_splunk_events(all_events)
    baseline_profile = derive_baseline_profile(events_df)
    features_df = build_feature_frame(events_df, baseline_profile=baseline_profile)
    feature_windows = features_df.to_dict(orient="records")

    print("[*] Running Rules-Only...")
    rules_detector = RulesOnlyDetector()
    rules_preds, rules_details = rules_detector.detect_with_details(feature_windows)
    
    # Map back to techniques
    fw_times = [pd.to_datetime(fw["timestamp"]).isoformat() for fw in feature_windows]
    truth_dict = {pd.to_datetime(w["time_window"]).isoformat(): w for w in window_labels}
    
    # Calculate per-technique recall for Rules
    technique_stats = {}
    for fw_time, pred, details in zip(fw_times, rules_preds, rules_details):
        truth = truth_dict.get(fw_time, {})
        label = truth.get("label")
        tech = truth.get("technique")
        if label == "malicious" and tech:
            if tech not in technique_stats:
                technique_stats[tech] = {"total": 0, "rules_detected": 0, "if_detected": 0}
            technique_stats[tech]["total"] += 1
            if pred:
                technique_stats[tech]["rules_detected"] += 1

    print("[*] Running CogniSOC ML Evaluation...")
    model = BehavioralAnomalyModel(contamination=0.05, random_state=42)
    model.train(features_df, baseline_profile)
    
    scored_features = model.score(features_df)
    findings_a = model.suspicious_findings(scored_features, min_score=90.0)
    
    finding_times = {pd.to_datetime(f.get("timestamp")).isoformat() for f in findings_a if f.get("timestamp")}
    
    for fw_time in fw_times:
        truth = truth_dict.get(fw_time, {})
        label = truth.get("label")
        tech = truth.get("technique")
        if label == "malicious" and tech:
            if fw_time in finding_times:
                technique_stats[tech]["if_detected"] += 1
                
    findings_b = correlate_incidents(findings_a)
    findings_c = prioritize_incidents(findings_b)
    
    priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for i in findings_c:
        p = i.get("priority_level")
        if p in priority_counts:
            priority_counts[p] += 1
            
    # Confusion matrices
    cm_rules = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    cm_if = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    
    for fw_time, rules_pred in zip(fw_times, rules_preds):
        truth_label = truth_dict.get(fw_time, {}).get("label") == "malicious"
        if truth_label:
            if rules_pred: cm_rules["tp"] += 1
            else: cm_rules["fn"] += 1
            if fw_time in finding_times: cm_if["tp"] += 1
            else: cm_if["fn"] += 1
        else:
            if rules_pred: cm_rules["fp"] += 1
            else: cm_rules["tn"] += 1
            if fw_time in finding_times: cm_if["fp"] += 1
            else: cm_if["tn"] += 1

    final_results = {
        "technique_recall": technique_stats,
        "priority_distribution": priority_counts,
        "confusion_matrices": {
            "rules": cm_rules,
            "isolation_forest": cm_if
        },
        "pipeline_volumes": {
            "Rules": sum(len(d) for d in rules_details),
            "Config_A_Raw": len(findings_a),
            "Config_B_Correlated": len(findings_b),
            "Config_C_Prioritized": len([i for i in findings_c if i.get("priority_level") in ["P1", "P2", "P3"]])
        }
    }
    
    output_file = Path("evaluation/results_expanded.json")
    output_file.write_text(json.dumps(final_results, indent=2))
    print("[*] Written to results_expanded.json")

if __name__ == "__main__":
    run_expanded_evaluation()
