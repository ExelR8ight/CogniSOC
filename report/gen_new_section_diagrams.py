import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import os

os.makedirs('images', exist_ok=True)

# -------------------------------------------------------
# 1. Development Methodology - Sprint Timeline / Gantt
# -------------------------------------------------------
fig, ax = plt.subplots(figsize=(12, 5))

sprints = [
    ('Sprint 1: Lab Setup &\nTelemetry Pipeline', 0, 3, '#1565c0'),
    ('Sprint 2: Data Ingestion\n& Parsing', 3, 2.5, '#0277bd'),
    ('Sprint 3: ML Engine &\nFeature Engineering', 5.5, 3, '#00838f'),
    ('Sprint 4: Correlation,\nSOAR Integration', 8.5, 2.5, '#00695c'),
    ('Sprint 5: Dashboards,\nTesting & Validation', 11, 3, '#2e7d32'),
]

for i, (label, start, duration, color) in enumerate(sprints):
    y = len(sprints) - i - 1
    bar = patches.FancyBboxPatch((start, y - 0.3), duration, 0.6,
                                  boxstyle="round,pad=0.1",
                                  facecolor=color, edgecolor='white', linewidth=2, alpha=0.9)
    ax.add_patch(bar)
    ax.text(start + duration / 2, y, label, ha='center', va='center',
            fontsize=9, fontweight='bold', color='white')

ax.set_xlim(-0.5, 15)
ax.set_ylim(-0.8, len(sprints) - 0.2)
ax.set_xlabel('Weeks', fontsize=12, fontweight='bold')
ax.set_xticks(range(0, 15))
ax.set_xticklabels([f'W{i+1}' for i in range(15)], fontsize=9)
ax.set_yticks([])
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_visible(False)

plt.title('CogniSOC Development Timeline (Agile-Iterative Sprints)', fontsize=14, fontweight='bold', color='#333333', pad=15)
plt.tight_layout()
plt.savefig('images/development_timeline.png', dpi=150, bbox_inches='tight', facecolor='white')
plt.close()
print("1/2 Development timeline generated.")

# -------------------------------------------------------
# 2. Quantitative Results - Anomaly Score Bar Chart
# -------------------------------------------------------
fig, ax = plt.subplots(figsize=(11, 5.5))

techniques = ['T1059.001\nPowerShell', 'T1003.001\nCred Dump', 'T1110.001\nBrute Force',
              'T1048.003\nExfiltration', 'T1218.010\nRegsvr32', 'T1218.011\nRundll32',
              'T1046\nPort Scan']
if_scores = [96.23, 94.17, 89.44, 87.92, 91.55, 90.33, 95.67]
dev_scores = [99.47, 97.81, 95.33, 93.67, 96.12, 94.88, 98.21]

x = np.arange(len(techniques))
width = 0.35

bars1 = ax.bar(x - width/2, if_scores, width, label='Isolation Forest Percentile',
               color='#1565c0', alpha=0.85, edgecolor='white', linewidth=1)
bars2 = ax.bar(x + width/2, dev_scores, width, label='Baseline Deviation Score',
               color='#c62828', alpha=0.85, edgecolor='white', linewidth=1)

# Threshold line
ax.axhline(y=90, color='#ff6f00', linewidth=2, linestyle='--', alpha=0.8, label='Detection Threshold (90)')

# Labels on bars
for bar in bars1:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 0.5, f'{height:.1f}',
            ha='center', va='bottom', fontsize=8, fontweight='bold', color='#1565c0')
for bar in bars2:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 0.5, f'{height:.1f}',
            ha='center', va='bottom', fontsize=8, fontweight='bold', color='#c62828')

ax.set_ylabel('Anomaly Score', fontsize=12, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(techniques, fontsize=9)
ax.set_ylim(80, 105)
ax.legend(loc='lower right', fontsize=9)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.set_title('Dual-Score Detection Results Across ATT&CK Techniques', fontsize=14, fontweight='bold', color='#333333', pad=15)

plt.tight_layout()
plt.savefig('images/detection_results_chart.png', dpi=150, bbox_inches='tight', facecolor='white')
plt.close()
print("2/2 Detection results chart generated.")

print("Done!")
