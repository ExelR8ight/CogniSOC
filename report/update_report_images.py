import re

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace Lab Network Topology
content = re.sub(
    r'#figure\(\s*rect.*?INSERT DIAGRAM: Lab Architecture.*?images/lab_network_topology\.png.*?\]\s*\]\s*\],\s*caption:\s*\[(.*?)\],\s*kind:\s*image,\s*\)\s*<fig-lab-arch>',
    r'#figure(\n  image("images/lab_network_topology.png", width: 100%),\n  caption: [\1],\n) <fig-lab-arch>',
    content,
    flags=re.DOTALL
)

# Replace System Dataflow
content = re.sub(
    r'#figure\(\s*rect.*?INSERT DIAGRAM: System Dataflow Architecture.*?images/system_dataflow\.png.*?\]\s*\]\s*\],\s*caption:\s*\[(.*?)\],\s*kind:\s*image,\s*\)\s*<fig-sys-arch>',
    r'#figure(\n  image("images/system_dataflow.png", width: 100%),\n  caption: [\1],\n) <fig-sys-arch>',
    content,
    flags=re.DOTALL
)

# Replace Telemetry Workflow
content = re.sub(
    r'#figure\(\s*rect.*?INSERT DIAGRAM: Telemetry Data Flow Workflow.*?images/telemetry_workflow_diagram\.png.*?\]\s*\]\s*\],\s*caption:\s*\[(.*?)\],\s*kind:\s*image,\s*\)\s*<fig-telemetry-workflow>',
    r'#figure(\n  image("images/telemetry_workflow_diagram.png", width: 100%),\n  caption: [\1],\n) <fig-telemetry-workflow>',
    content,
    flags=re.DOTALL
)

# Replace Incident Response Workflow
content = re.sub(
    r'#figure\(\s*rect.*?INSERT DIAGRAM: Incident Response & Automation Workflow.*?images/incident_response_workflow\.png.*?\]\s*\]\s*\],\s*caption:\s*\[(.*?)\],\s*kind:\s*image,\s*\)\s*<fig-ir-workflow>',
    r'#figure(\n  image("images/incident_response_workflow.png", width: 100%),\n  caption: [\1],\n) <fig-ir-workflow>',
    content,
    flags=re.DOTALL
)

with open('main.typ', 'w', encoding='utf-8') as f:
    f.write(content)

