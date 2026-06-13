import matplotlib.pyplot as plt
import matplotlib.patches as patches
import os

# Create images dir if not exists
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
# 1. Lab Network Topology
# -----------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 6))
ax.set_xlim(0, 10)
ax.set_ylim(0, 6)
ax.axis('off')

draw_box(ax, 1, 3.5, 2.5, 1.5, "Kali Linux\n(Attacker VM)\n192.168.1.100", '#ffcdd2', '#c62828')
draw_box(ax, 6.5, 3.5, 2.5, 1.5, "Windows 10\n(Victim VM)\n192.168.1.101", '#e1f5fe', '#01579b')
draw_box(ax, 1, 0.5, 2.5, 1.5, "Ubuntu Server\n(SIEM / ML Engine)\n192.168.1.102", '#e8f5e9', '#2e7d32')
draw_box(ax, 6.5, 0.5, 2.5, 1.5, "Splunk Enterprise\n(Indexer / Search)\n192.168.1.103", '#fff3e0', '#ef6c00')

draw_arrow(ax, 3.5, 4.25, 6.5, 4.25, "Attack Traffic\n(Atomic Red Team)")
draw_arrow(ax, 7.75, 3.5, 7.75, 2.0, "Telemetry")
draw_arrow(ax, 6.5, 1.25, 3.5, 1.25, "REST API Fetch")

plt.title("Lab Architecture Topology", fontsize=16, fontweight='bold', color='#333333', pad=20)
plt.tight_layout()
plt.savefig('images/lab_network_topology.png', dpi=150, bbox_inches='tight')
plt.close()


# -----------------------------------------------------
# 2. Telemetry Workflow
# -----------------------------------------------------
fig, ax = plt.subplots(figsize=(12, 4))
ax.set_xlim(0, 12)
ax.set_ylim(0, 4)
ax.axis('off')

draw_box(ax, 0.5, 1.5, 2.5, 1.2, "Windows Endpoint\n(Sysmon / Suricata)", '#e1f5fe')
draw_box(ax, 4.5, 1.5, 3.0, 1.2, "Splunk Universal Forwarder\n(inputs.conf / outputs.conf)", '#f3e5f5')
draw_box(ax, 9.0, 1.5, 2.5, 1.2, "Splunk Indexer\n(main / suricata index)", '#fff3e0')

draw_arrow(ax, 3.0, 2.1, 4.5, 2.1, "Local Logs")
draw_arrow(ax, 7.5, 2.1, 9.0, 2.1, "TCP 9997")

plt.title("Telemetry Data Flow Workflow", fontsize=16, fontweight='bold', color='#333333')
plt.tight_layout()
plt.savefig('images/telemetry_workflow_diagram.png', dpi=150, bbox_inches='tight')
plt.close()


# -----------------------------------------------------
# 3. Incident Response Workflow
# -----------------------------------------------------
fig, ax = plt.subplots(figsize=(12, 6))
ax.set_xlim(0, 12)
ax.set_ylim(0, 6)
ax.axis('off')

draw_box(ax, 0.5, 3.5, 2.5, 1.2, "ML Isolation Forest\n(Anomaly Score > 90)", '#e8f5e9')
draw_box(ax, 4.5, 3.5, 2.5, 1.2, "Correlation Engine\n(Map to MITRE)", '#e1f5fe')
draw_box(ax, 8.5, 3.5, 2.5, 1.2, "Priority Scorer\n(P1 - P4)", '#ffe0b2')

draw_box(ax, 4.5, 1.0, 2.5, 1.2, "TheHive SOAR\n(Case Creation)", '#fce4ec')
draw_box(ax, 8.5, 1.0, 2.5, 1.2, "Splunk Dashboard\n(HEC Ingest)", '#fff3e0')

draw_arrow(ax, 3.0, 4.1, 4.5, 4.1, "Raw Findings")
draw_arrow(ax, 7.0, 4.1, 8.5, 4.1, "Correlated Alerts")
draw_arrow(ax, 9.75, 3.5, 9.75, 2.2, "Final Incidents")
draw_arrow(ax, 8.5, 1.6, 7.0, 1.6, "Webhooks / APIs")

plt.title("Incident Response & Automation Workflow", fontsize=16, fontweight='bold', color='#333333')
plt.tight_layout()
plt.savefig('images/incident_response_workflow.png', dpi=150, bbox_inches='tight')
plt.close()


# -----------------------------------------------------
# 4. System Dataflow
# -----------------------------------------------------
fig, ax = plt.subplots(figsize=(12, 6))
ax.set_xlim(0, 12)
ax.set_ylim(0, 6)
ax.axis('off')

draw_box(ax, 0.5, 3.5, 2.0, 1.0, "Telemetry Sources", '#e1f5fe')
draw_box(ax, 3.5, 3.5, 2.0, 1.0, "Splunk SIEM", '#fff3e0')
draw_box(ax, 6.5, 3.5, 2.0, 1.0, "CogniSOC Engine", '#e8f5e9')
draw_box(ax, 9.5, 3.5, 2.0, 1.0, "TheHive", '#fce4ec')
draw_box(ax, 6.5, 1.5, 2.0, 1.0, "Dash UI", '#f3e5f5')

draw_arrow(ax, 2.5, 4.0, 3.5, 4.0, "Logs")
draw_arrow(ax, 5.5, 4.0, 6.5, 4.0, "REST API")
draw_arrow(ax, 8.5, 4.0, 9.5, 4.0, "Alerts")
draw_arrow(ax, 7.5, 3.5, 7.5, 2.5, "Live Stats")
draw_arrow(ax, 6.5, 4.2, 5.5, 4.2, "HEC Push")

plt.title("End-to-End System Dataflow", fontsize=16, fontweight='bold', color='#333333')
plt.tight_layout()
plt.savefig('images/system_dataflow.png', dpi=150, bbox_inches='tight')
plt.close()

print("All diagrams generated successfully.")
