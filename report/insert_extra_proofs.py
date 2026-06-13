import re

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. vm_hypervisor_setup.png
block1 = '''
#figure(
  rect(width: 100%, height: 6cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 10pt, fill: gray)[
        SCREENSHOT: VirtualBox or VMware Workstation showing the 4 VMs \\
        (Main PC, Ubuntu SIEM, Victim Windows, Kali Attacker) running. \\
        \\
        File: eport/images/vm_hypervisor_setup.png
      ]
    ]
  ],
  caption: [Virtual machine hypervisor setup for the isolated SOC lab environment.],
  kind: image,
) <fig-vm-setup>
'''
content = content.replace(
    'The system was developed and tested in a virtualized lab environment consisting of four machines, each serving a distinct role in the SOC pipeline. @tab-lab-machines summarizes the configuration.',
    'The system was developed and tested in a virtualized lab environment consisting of four machines, each serving a distinct role in the SOC pipeline. @tab-lab-machines summarizes the configuration.\n' + block1
)

# 2. code_anomaly_model.png
block2 = '''
#figure(
  rect(width: 100%, height: 7cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 10pt, fill: gray)[
        SCREENSHOT: Code snippet from models/anomaly_model.py showing \\
        the IsolationForest initialization and dual-score logic. \\
        \\
        File: eport/images/code_anomaly_model.png
      ]
    ]
  ],
  caption: [Python implementation of the dual-score Isolation Forest anomaly model.],
  kind: image,
) <fig-code-anomaly-model>
'''
content = content.replace(
    'The Isolation Forest model is configured with the following hyperparameters:',
    'The Isolation Forest model is configured with the following hyperparameters:\n' + block2
)

# 3. splunk_spl_query.png
block3 = '''
#figure(
  rect(width: 100%, height: 5cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 10pt, fill: gray)[
        SCREENSHOT: Splunk Web showing a complex SPL query used to fetch \\
        or visualize NIDS/Sysmon data, proving query competence. \\
        \\
        File: eport/images/splunk_spl_query.png
      ]
    ]
  ],
  caption: [Splunk Search Processing Language (SPL) query for advanced threat hunting.],
  kind: image,
) <fig-splunk-spl-query>
'''
content = content.replace(
    '== Sigma Detection Rules',
    block3 + '\n\n== Sigma Detection Rules'
)

# 4. sigma_rule_example.png
block4 = '''
#figure(
  rect(width: 100%, height: 6cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 10pt, fill: gray)[
        SCREENSHOT: A snippet of one of the custom Sigma YAML files \\
        (e.g., detecting rare PowerShell execution). \\
        \\
        File: eport/images/sigma_rule_example.png
      ]
    ]
  ],
  caption: [Example of a custom Sigma detection rule in YAML format.],
  kind: image,
) <fig-sigma-rule>
'''
content = content.replace(
    'The project includes 13 custom Sigma rules written in YAML format, covering the following attack scenarios:',
    'The project includes 13 custom Sigma rules written in YAML format, covering the following attack scenarios:\n' + block4
)

# 5. suricata_config.png
block5 = '''
#figure(
  rect(width: 100%, height: 5cm, stroke: 1pt + gray)[
    #align(center + horizon)[
      #text(size: 10pt, fill: gray)[
        SCREENSHOT: Snippet of the modified suricata.yaml file \\
        showing the eve-log JSON output configuration. \\
        \\
        File: eport/images/suricata_config.png
      ]
    ]
  ],
  caption: [Optimized Suricata configuration for nested JSON alert logging.],
  kind: image,
) <fig-suricata-config>
'''
content = content.replace(
    'extract deep nested keys (e.g., lert.signature) regardless of the event type.',
    'extract deep nested keys (e.g., lert.signature) regardless of the event type.\n' + block5
)

with open('main.typ', 'w', encoding='utf-8') as f:
    f.write(content)
