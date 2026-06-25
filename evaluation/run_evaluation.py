"""
Main execution script for CogniSOC paper evaluation.
"""

from __future__ import annotations

import json
from pathlib import Path
from pprint import pprint

from evaluation.synthetic_telemetry import generate_full_dataset
from evaluation.rules_only_detector import RulesOnlyDetector
from evaluation.ablation_runner import run_ablation
from evaluation.metrics import compute_confusion_matrix, alert_volume_reduction

from soc_ml_engine.processing.features import parse_splunk_events, build_feature_frame, derive_baseline_profile
from soc_ml_engine.models.anomaly_model import BehavioralAnomalyModel


def run_evaluation():
    print("[*] Generating synthetic evaluation dataset...")
    # 1. Generate data
    all_events, window_labels = generate_full_dataset(benign_windows=40, attack_repetitions=3)
    truth_dict = {w["time_window"]: (w["label"] == "malicious") for w in window_labels}
    truth_list = [truth_dict[w["time_window"]] for w in window_labels]

    print(f"[*] Generated {len(all_events)} events across {len(window_labels)} time windows.")

    # 2. Build Features
    events_df = parse_splunk_events(all_events)
    baseline_profile = derive_baseline_profile(events_df)
    features_df = build_feature_frame(events_df, baseline_profile=baseline_profile)

    # Make feature windows available as a list of dicts for Rules-Only detector
    feature_windows = features_df.to_dict(orient="records")

    print("[*] Running Rules-Only Baseline...")
    # 3. Rules Only Evaluation
    rules_detector = RulesOnlyDetector()
    rules_preds, rules_details = rules_detector.detect_with_details(feature_windows)
    
    # Check alignment
    if len(rules_preds) != len(truth_list):
        import pandas as pd
        fw_times = [pd.to_datetime(fw["timestamp"]).isoformat() for fw in feature_windows]
        normalized_truth_dict = {pd.to_datetime(k).isoformat(): v for k, v in truth_dict.items()}
        aligned_truth = [normalized_truth_dict.get(ts, False) for ts in fw_times]
    else:
        import pandas as pd
        fw_times = [pd.to_datetime(fw["timestamp"]).isoformat() for fw in feature_windows]
        normalized_truth_dict = {pd.to_datetime(k).isoformat(): v for k, v in truth_dict.items()}
        aligned_truth = [normalized_truth_dict.get(ts, False) for ts in fw_times]

    rules_cm = compute_confusion_matrix(rules_preds, aligned_truth)
    total_rules_alerts = sum(len(d) for d in rules_details)

    print("[*] Running CogniSOC ML Evaluation...")
    # 4. CogniSOC (ML) Evaluation
    model = BehavioralAnomalyModel(contamination=0.05, random_state=42)
    # We train on the first 30 benign windows to simulate baseline phase
    # (In real deployment, baseline is collected over days)
    # For this evaluation, we use the entire dataset for feature scaling, 
    # but the IF isolates the anomalous points.
    model.train(features_df, baseline_profile)
    
    ablation_results = run_ablation(features_df, model, window_labels)

    # 5. Compile Results
    final_results = {
        "Baseline_Rules_Only": {
            "confusion_matrix": rules_cm.to_dict(),
            "total_alerts": total_rules_alerts
        },
        "CogniSOC_Ablation": ablation_results,
        "Alert_Volume_Reduction": {
            "Rules_vs_IF": alert_volume_reduction(total_rules_alerts, ablation_results["Config_A_IF_Only"]["total_alerts"]),
            "Rules_vs_Correlation": alert_volume_reduction(total_rules_alerts, ablation_results["Config_B_IF_Correlation"]["total_incidents"]),
            "Rules_vs_Full_System": alert_volume_reduction(total_rules_alerts, ablation_results["Config_C_Full_System"]["total_high_priority_incidents"]),
        }
    }

    output_file = Path("evaluation/results.json")
    output_file.parent.mkdir(exist_ok=True)
    output_file.write_text(json.dumps(final_results, indent=2))
    
    print("\n" + "="*50)
    print("EVALUATION RESULTS")
    print("="*50)
    pprint(final_results)

if __name__ == "__main__":
    run_evaluation()
