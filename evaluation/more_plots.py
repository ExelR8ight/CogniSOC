import json
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def generate_more_plots():
    results_path = Path("evaluation/results_expanded.json")
    if not results_path.exists():
        print("Run expanded evaluation first.")
        return

    with open(results_path, "r") as f:
        data = json.load(f)

    out_dir = Path("evaluation/figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Confusion Matrix Heatmaps
    cm_rules = data["confusion_matrices"]["rules"]
    cm_if = data["confusion_matrices"]["isolation_forest"]
    
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    
    sns.heatmap([[cm_rules["tn"], cm_rules["fp"]], [cm_rules["fn"], cm_rules["tp"]]], 
                annot=True, fmt="d", cmap="Blues", cbar=False, ax=axes[0],
                xticklabels=["Benign", "Malicious"], yticklabels=["Benign", "Malicious"])
    axes[0].set_title("Rules-Only Baseline")
    axes[0].set_xlabel("Predicted")
    axes[0].set_ylabel("Actual")
    
    sns.heatmap([[cm_if["tn"], cm_if["fp"]], [cm_if["fn"], cm_if["tp"]]], 
                annot=True, fmt="d", cmap="Oranges", cbar=False, ax=axes[1],
                xticklabels=["Benign", "Malicious"], yticklabels=["Benign", "Malicious"])
    axes[1].set_title("Isolation Forest (CogniSOC)")
    axes[1].set_xlabel("Predicted")
    axes[1].set_ylabel("Actual")
    
    plt.tight_layout()
    plt.savefig(out_dir / "confusion_matrices.png", dpi=300)
    plt.close()

    # 2. Recall by Technique Bar Chart
    techs = data["technique_recall"]
    labels = list(techs.keys())
    rules_recall = [techs[t]["rules_detected"] / techs[t]["total"] * 100 for t in labels]
    if_recall = [techs[t]["if_detected"] / techs[t]["total"] * 100 for t in labels]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x - width/2, rules_recall, width, label='Rules-Only', color='#1f77b4')
    ax.bar(x + width/2, if_recall, width, label='Isolation Forest', color='#ff7f0e')

    ax.set_ylabel('Recall (%)')
    ax.set_title('Detection Recall by MITRE ATT&CK Technique')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.legend()
    ax.set_ylim(0, 110)
    
    plt.tight_layout()
    plt.savefig(out_dir / "recall_by_technique.png", dpi=300)
    plt.close()

    # 3. Priority Distribution Pie Chart
    priorities = data["priority_distribution"]
    labels_p = []
    sizes = []
    colors = []
    color_map = {"P1": "#d62728", "P2": "#ff7f0e", "P3": "#ffbb78", "P4": "#c7c7c7"}
    
    for p, count in priorities.items():
        if count > 0:
            labels_p.append(p)
            sizes.append(count)
            colors.append(color_map[p])

    if sum(sizes) > 0:
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.pie(sizes, labels=labels_p, colors=colors, autopct='%1.1f%%', startangle=140)
        ax.set_title('Distribution of Incident Priorities')
        plt.tight_layout()
        plt.savefig(out_dir / "priority_distribution.png", dpi=300)
        plt.close()

    print("[*] Expanded plots generated.")

if __name__ == "__main__":
    generate_more_plots()
