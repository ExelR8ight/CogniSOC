import re

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Replace Lab Network Topology
content = re.sub(
    r'#figure\(\s*rect\(.*?lab_network_topology\.png.*?\]\s*\],\s*caption: \[Lab network topology diagram\.\],\s*kind: image,\s*\) <fig-lab-topology>',
    r'#figure(\n  image("images/lab_network_topology.png", width: 100%),\n  caption: [Lab network topology diagram.],\n  kind: image,\n) <fig-lab-topology>',
    content,
    flags=re.DOTALL
)

# 2. Replace System Dataflow
content = re.sub(
    r'#figure\(\s*rect\(.*?system_dataflow\.png.*?\]\s*\],\s*caption: \[Complete system data flow from telemetry generation to incident response\.\],\s*kind: image,\s*\) <fig-sys-dataflow>',
    r'#figure(\n  image("images/system_dataflow.png", width: 100%),\n  caption: [Complete system data flow from telemetry generation to incident response.],\n  kind: image,\n) <fig-sys-dataflow>',
    content,
    flags=re.DOTALL
)

# 3. Add Telemetry Workflow if missing
if '<fig-telemetry-workflow>' not in content:
    tele_workflow_block = '''
#figure(
  image("images/telemetry_workflow_diagram.png", width: 100%),
  caption: [Telemetry collection and forwarding data flow.],
  kind: image,
) <fig-telemetry-workflow>
'''
    content = content.replace('=== Splunk Universal Forwarder Configuration\n\n', '=== Splunk Universal Forwarder Configuration\n' + tele_workflow_block + '\n')

# 4. Add Incident Response Workflow if missing
if '<fig-ir-workflow>' not in content:
    ir_workflow_block = '''
#figure(
  image("images/incident_response_workflow.png", width: 100%),
  caption: [Automated incident correlation and SOAR response workflow.],
  kind: image,
) <fig-ir-workflow>
'''
    content = content.replace('=== Incident Correlation and Aggregation\n\n', '=== Incident Correlation and Aggregation\n' + ir_workflow_block + '\n')

with open('main.typ', 'w', encoding='utf-8') as f:
    f.write(content)
