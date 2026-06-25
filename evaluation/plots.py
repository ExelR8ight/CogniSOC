"""
Generate figures and plots for the CogniSOC research paper.
"""

from __future__ import annotations

import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

def generate_plots():
    results_path = Path("evaluation/results.json")
    if not results_path.exists():
        print("Results file not found. Run evaluation first.")
        return

    with open(results_path, "r") as f:
        results = json.load(f)

    out_dir = Path("evaluation/figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Precision/Recall/F1 Bar Chart
    rules = results["Baseline_Rules_Only"]["confusion_matrix"]
    if_only = results["CogniSOC_Ablation"]["Config_A_IF_Only"]

    metrics = ("Precision", "Recall", "F1-Score")
    rules_vals = (rules["precision"] * 100, rules["recall"] * 100, rules["f1"] * 100)
    if_vals = (if_only["precision"] * 100, if_only["recall"] * 100, if_only["f1"] * 100)

    x = np.arange(len(metrics))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - width/2, rules_vals, width, label='Rules-Only (Baseline)', color='#1f77b4')
    ax.bar(x + width/2, if_vals, width, label='Isolation Forest (CogniSOC)', color='#ff7f0e')

    ax.set_ylabel('Percentage (%)')
    ax.set_title('Detection Performance Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.legend()
    ax.set_ylim(0, 110)

    # Add labels on top of bars
    for i, v in enumerate(rules_vals):
        ax.text(i - width/2, v + 2, f'{v:.1f}%', ha='center', va='bottom', fontsize=9)
    for i, v in enumerate(if_vals):
        ax.text(i + width/2, v + 2, f'{v:.1f}%', ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig(out_dir / "performance_comparison.pdf")
    plt.savefig(out_dir / "performance_comparison.png", dpi=300)
    plt.close()

    # 2. Alert Volume Comparison
    rules_alerts = results["Baseline_Rules_Only"]["total_alerts"]
    if_alerts = results["CogniSOC_Ablation"]["Config_A_IF_Only"]["total_alerts"]
    if_corr_alerts = results["CogniSOC_Ablation"]["Config_B_IF_Correlation"]["total_incidents"]
    full_sys_alerts = results["CogniSOC_Ablation"]["Config_C_Full_System"]["total_high_priority_incidents"]

    stages = ('Rules-Only\n(Alerts)', 'IF Only\n(Anomalies)', 'IF + Correlation\n(Incidents)', 'Full System\n(Prioritized)')
    volumes = (rules_alerts, if_alerts, if_corr_alerts, full_sys_alerts)

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(stages, volumes, color=['#d62728', '#ff7f0e', '#2ca02c', '#1f77b4'])

    ax.set_ylabel('Alert Volume')
    ax.set_title('Alert Volume Reduction Pipeline')
    
    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + 0.2, int(yval), ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig(out_dir / "alert_volume_reduction.pdf")
    plt.savefig(out_dir / "alert_volume_reduction.png", dpi=300)
    plt.close()

    print(f"[*] Generated plots in {out_dir}/")


if __name__ == "__main__":
    generate_plots()
