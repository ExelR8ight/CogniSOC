import re

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace Title Page Header
old_header = '''  #text(size: 14pt, weight: "bold")[
    NOIDA INSTITUTE OF ENGINEERING AND TECHNOLOGY \\
    (NIET, Greater Noida)
  ]

  #v(0.3cm)
  #text(size: 12pt)[
    Affiliated to Dr. A.P.J. Abdul Kalam Technical University, Lucknow
  ]

  #v(0.5cm)
  // -- PLACEHOLDER: University Logo --
  #rect(width: 4cm, height: 4cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 9pt, fill: gray)[
        INSERT UNIVERSITY LOGO \\
        eport/images/niet_logo.png
      ]
    ]
  ]
  // To use a real logo, replace the rect above with:
  // #image("images/niet_logo.png", width: 4cm)

  #v(0.8cm)
  #text(size: 12pt, weight: "bold")[DEPARTMENT OF CYBER SECURITY]'''

new_header = '''  #text(size: 16pt, weight: "bold")[
    HCLTech Internship Project Report
  ]

  #v(0.3cm)
  #text(size: 12pt)[
    Cyber Security Engineering Division
  ]

  #v(0.5cm)
  // -- PLACEHOLDER: HCLTech Logo --
  #rect(width: 4cm, height: 4cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 9pt, fill: gray)[
        INSERT HCLTECH LOGO \\
        eport/images/hcltech_logo.png
      ]
    ]
  ]
  // To use a real logo, replace the rect above with:
  // #image("images/hcltech_logo.png", width: 4cm)

  #v(0.8cm)'''

content = content.replace(old_header, new_header)

# Add Data Flow Diagram placeholder in Chapter 4 (Implementation)
if '== Forwarder Configuration' in content:
    workflow_1 = '''== Forwarder Configuration

#figure(
  rect(width: 100%, height: 7cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 10pt, fill: gray)[
        INSERT DIAGRAM: Telemetry Data Flow Workflow \\
        (Showing Victim VM -> Sysmon/Suricata -> Splunk Universal Forwarder -> Splunk Indexer) \\
        File: eport/images/telemetry_workflow_diagram.png
      ]
    ]
  ],
  caption: [Telemetry collection and forwarding data flow.],
) <fig-telemetry-workflow>

'''
    content = content.replace('== Forwarder Configuration\n', workflow_1)

# Add Incident Response Workflow placeholder in Chapter 6
if '== Automated Incident Push to TheHive' in content:
    workflow_2 = '''== Automated Incident Push to TheHive

#figure(
  rect(width: 100%, height: 8cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 10pt, fill: gray)[
        INSERT DIAGRAM: Incident Response & Automation Workflow \\
        (Showing ML Output -> Correlator -> Priority Scorer -> TheHive Case Creation -> Splunk Dashboard) \\
        File: eport/images/incident_response_workflow.png
      ]
    ]
  ],
  caption: [Automated incident correlation and SOAR response workflow.],
) <fig-ir-workflow>

'''
    content = content.replace('== Automated Incident Push to TheHive\n', workflow_2)


with open('main.typ', 'w', encoding='utf-8') as f:
    f.write(content)

