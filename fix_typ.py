import re

with open('report/main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

new_dashboard_typst = '''#figure(
  image("images/splunk_soc_dashboard_1.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (Overview & MITRE ATT&CK Mapping)],
  kind: image,
) <fig-splunk-dashboard-1>

#figure(
  image("images/splunk_soc_dashboard_2.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (Incident Types & Correlated Alerts)],
  kind: image,
) <fig-splunk-dashboard-2>

#figure(
  image("images/splunk_soc_dashboard_3.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (Suspicious Process Creations)],
  kind: image,
) <fig-splunk-dashboard-3>

#figure(
  image("images/splunk_soc_dashboard_4.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (Incoming Data Sources & Remediation)],
  kind: image,
) <fig-splunk-dashboard-4>

#figure(
  image("images/splunk_soc_dashboard_5.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (Threat Intel & IP Reputation)],
  kind: image,
) <fig-splunk-dashboard-5>

#figure(
  image("images/splunk_soc_dashboard_6.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (Detection Audit Logs)],
  kind: image,
) <fig-splunk-dashboard-6>

#figure(
  image("images/splunk_soc_dashboard_7.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (Network Traffic Analysis)],
  kind: image,
) <fig-splunk-dashboard-7>

#figure(
  image("images/splunk_soc_dashboard_8.png", width: 100%),
  caption: [Splunk SOC Command Center Dashboard (System Health & SIEM Status)],
  kind: image,
) <fig-splunk-dashboard-8>

*Dashboard Analysis & Explanation of Missing Results:*
The screenshots above capture the complete Splunk SOC Command Center dashboard in its deployed state. The dashboard features panels for MITRE ATT&CK alignment, suspicious process tracking, threat intelligence lookups, and incoming data volume. 

*Note on 'No search results returned':* In some of the dashboard panels (such as specific Threat Intel file hash lookups or Top DNS Queries), the tables may display 'No search results returned'. This is expected behavior in our lab environment for the following reasons:
1. *Targeted Attack Simulations:* The Atomic Red Team simulations run during testing primarily focus on specific vectors like PowerShell abuse (T1059.001) and credential dumping. If a specific technique like lateral movement or rare DNS exfiltration was not simulated in the selected time range, those dedicated panels will naturally be empty.
2. *Threat Intel Lookups:* Panels relying on external threat intelligence lookups (like AbuseIPDB/OTX) require active connections to known malicious external IPs. Since the lab operates in a somewhat isolated or internal network setup, external IP reputation matches may not always trigger unless explicitly mocked.
3. *Time Range Filtering:* Dashboard panels are highly sensitive to the selected time range (e.g., 'Last 24 hours'). If the attack simulation completed outside of the specific window when the screenshot was taken, the active incident tables will show no active search results.
'''

pattern = r'#figure\(\s*grid\(\s*columns: 1,\s*row-gutter: 10pt,.*?</fig-splunk-dashboard>'

content = re.sub(pattern, new_dashboard_typst, content, flags=re.DOTALL)

with open('report/main.typ', 'w', encoding='utf-8') as f:
    f.write(content)
print('Updated main.typ!')
