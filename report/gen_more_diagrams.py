import matplotlib.pyplot as plt
import matplotlib.patches as patches
import os

os.makedirs('images', exist_ok=True)

def draw_box(ax, x, y, width, height, text, bg_color='#e1f5fe', text_color='black', fontsize=12):
    rect = patches.Rectangle((x, y), width, height, linewidth=1.5, edgecolor='#01579b', facecolor=bg_color, zorder=2)
    ax.add_patch(rect)
    ax.text(x + width/2, y + height/2, text, color=text_color, fontsize=fontsize, 
            ha='center', va='center', fontweight='bold', zorder=3, wrap=True)

def draw_arrow(ax, x1, y1, x2, y2, text=""):
    ax.annotate(text, xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(facecolor='#0277bd', edgecolor='#0277bd', shrink=0.05, width=2, headwidth=8),
                fontsize=10, ha='center', va='bottom', color='#0277bd', zorder=1)

# -----------------------------------------------------
# 5. ML Feature Engineering & Scoring Pipeline
# -----------------------------------------------------
fig, ax = plt.subplots(figsize=(12, 6))
ax.set_xlim(0, 12)
ax.set_ylim(0, 6)
ax.axis('off')

draw_box(ax, 0.5, 3.5, 2.0, 1.2, "Raw Telemetry\n(JSON)", '#e1f5fe')
draw_box(ax, 3.5, 3.5, 2.0, 1.2, "Feature Extraction\n(Time-windowed)", '#fff3e0')
draw_box(ax, 6.5, 3.5, 2.0, 1.2, "StandardScaler &\nOne-Hot Encoding", '#f3e5f5')
draw_box(ax, 9.5, 3.5, 2.0, 1.2, "Isolation Forest\n(Anomaly Model)", '#e8f5e9')

draw_box(ax, 9.5, 1.0, 2.0, 1.2, "Anomaly Score\n(0-100)", '#ffcdd2', '#c62828')

draw_arrow(ax, 2.5, 4.1, 3.5, 4.1, "Parse")
draw_arrow(ax, 5.5, 4.1, 6.5, 4.1, "Vectorize")
draw_arrow(ax, 8.5, 4.1, 9.5, 4.1, "Train/Predict")
draw_arrow(ax, 10.5, 3.5, 10.5, 2.2, "Calculate")

plt.title("Machine Learning Feature Engineering & Scoring Pipeline", fontsize=16, fontweight='bold', color='#333333')
plt.tight_layout()
plt.savefig('images/ml_pipeline_diagram.png', dpi=150, bbox_inches='tight')
plt.close()

# -----------------------------------------------------
# 6. Correlation Engine Logic
# -----------------------------------------------------
fig, ax = plt.subplots(figsize=(12, 6))
ax.set_xlim(0, 12)
ax.set_ylim(0, 6)
ax.axis('off')

draw_box(ax, 0.5, 4.0, 2.5, 1.0, "Anomalous Events\n(Score >= 90)", '#ffcdd2')
draw_box(ax, 0.5, 2.0, 2.5, 1.0, "Normal Events\n(Context)", '#e1f5fe')

draw_box(ax, 4.5, 3.0, 3.0, 2.0, "Six-Rule Correlation Engine\n\n1. Recon\n2. PowerShell\n3. Brute Force\n...", '#fff3e0')

draw_box(ax, 9.0, 4.0, 2.5, 1.0, "Correlated Incident\n(MITRE Mapped)", '#e8f5e9')
draw_box(ax, 9.0, 2.0, 2.5, 1.0, "Priority Scorer\n(P1 - P4)", '#f3e5f5')

draw_arrow(ax, 3.0, 4.5, 4.5, 4.5, "Input")
draw_arrow(ax, 3.0, 2.5, 4.5, 3.5, "Context")
draw_arrow(ax, 7.5, 4.5, 9.0, 4.5, "Match")
draw_arrow(ax, 10.25, 4.0, 10.25, 3.0, "Evaluate")

plt.title("Rule-Based Correlation & Prioritization Engine", fontsize=16, fontweight='bold', color='#333333')
plt.tight_layout()
plt.savefig('images/correlation_engine_diagram.png', dpi=150, bbox_inches='tight')
plt.close()

print("New diagrams generated successfully.")
