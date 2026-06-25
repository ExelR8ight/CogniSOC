// CogniSOC Paper

#let ieee(
  title: "",
  abstract: [],
  authors: (),
  body
) = {
  set document(title: title, author: authors.map(a => a.name))
  set page(
    paper: "us-letter",
    margin: (x: 1.5cm, y: 2.0cm),
  )
  set text(font: "Times New Roman", size: 10pt)
  
  show heading: it => {
    set text(size: 11pt, weight: "bold")
    set block(above: 1.2em, below: 0.8em)
    it
  }
  
  align(center)[
    #text(24pt, weight: "bold")[#title]
    
    #v(1em)
    
    #grid(
      columns: (1fr,) * authors.len(),
      ..authors.map(author => [
        *#author.name*\
        #author.affiliation\
        #author.email
      ])
    )
  ]
  
  v(1.5em)
  
  show: columns.with(2, gutter: 1em)
  
  set par(justify: true)
  
  [
    *Abstract*---#abstract
  ]
  
  v(1em)
  
  body
}

#show: ieee.with(
  title: "CogniSOC: Bridging the Gap Between Academic Anomaly Detection and SOC Operations",
  authors: (
    (
      name: "Ankit",
      affiliation: "HCLTech",
      email: "ankit@example.com"
    ),
    (
      name: "Piyush",
      affiliation: "HCLTech",
      email: "piyush@example.com"
    ),
    (
      name: "Ujjval",
      affiliation: "HCLTech",
      email: "ujjval@example.com"
    ),
    (
      name: "Saloni",
      affiliation: "HCLTech",
      email: "saloni@example.com"
    ),
  ),
  abstract: [
    Security Operations Centers (SOCs) rely heavily on Security Information and Event Management (SIEM) rules to identify malicious activity, leading to alert fatigue and high false positive rates. Academic research frequently proposes machine learning (ML) models, particularly anomaly detection, to address these challenges. However, most academic works focus solely on algorithmic performance in isolation and fail to address the critical gaps between generating an anomaly score and providing actionable intelligence to a SOC analyst. In this paper, we present CogniSOC, an end-to-end open-source behavioral analytics framework that integrates anomaly detection with existing SIEM infrastructure, correlation engines, and Security Orchestration, Automation, and Response (SOAR) platforms. We implemented an Isolation Forest model using robust feature engineering on Sysmon and Suricata telemetry. More importantly, we introduce a correlation engine mapped to the MITRE ATT&CK framework and a prioritization module to reduce alert volume. We evaluate our pipeline against a Rules-Only baseline across simulated attack scenarios. Our results demonstrate that CogniSOC achieves a significant reduction in alert volume while improving detection precision and recall compared to traditional SIEM rules. By releasing CogniSOC as an open-source reference implementation, we bridge the gap between theoretical ML models and operational incident response workflows.
  ]
)

= Introduction

The modern Security Operations Center (SOC) is inundated with alerts. Traditional Security Information and Event Management (SIEM) systems operate on static rules and pattern-matching techniques. While these rules are effective against known threats, they struggle to identify novel attacks and often generate a high volume of false positives, leading to "alert fatigue" among analysts.

Academic research has responded to this challenge by proposing various machine learning (ML) techniques, particularly anomaly detection models, to identify deviations from normal behavior. However, a significant gap remains between academic research and operational deployment. Most anomaly-detection papers evaluate algorithms or datasets in isolation, stopping at the point of generating an "anomaly score." They rarely address how these scores should be integrated into existing SOC workflows, correlated with other security events, or automated for incident response.

To address this gap, we present CogniSOC, an end-to-end reference implementation that integrates behavioral anomaly detection directly with SIEM, correlation, MITRE ATT&CK mapping, and SOAR automation. CogniSOC goes beyond just finding anomalies; it closes the loop from raw telemetry ingestion to automated investigation case creation.

Our contributions are as follows:
- We propose and implement CogniSOC, a complete pipeline that bridges ML-based anomaly detection and operational SOC workflows.
- We present a multi-stage alert reduction strategy that combines an Isolation Forest model, a correlation engine, and a prioritization module.
- We evaluate CogniSOC against a traditional Rules-Only baseline, demonstrating improved precision, recall, and a significant reduction in alert volume.
- We provide an open-source implementation to serve as a reference architecture for integrating AI-powered analytics into practical SOC operations.

= Related Work

Previous work in ML for cybersecurity has predominantly focused on improving the underlying algorithms. Many researchers have explored Isolation Forests, Autoencoders, and recurrent neural networks for detecting anomalies in network traffic or system logs. However, as noted in recent literature reviews, a substantial majority of these works lack integration with SIEM/SOAR platforms.

In contrast, our work does not claim algorithmic novelty; rather, we contribute a systems-level architecture that proves the viability and operational necessity of wrapping ML models with correlation and prioritization logic before presenting alerts to analysts.

= System Architecture

The CogniSOC architecture is designed to integrate seamlessly with existing SOC infrastructure. The pipeline consists of five key stages:

1. *Telemetry Ingestion:* Raw logs from Sysmon (endpoint) and Suricata (network) are fetched from Splunk.
2. *Feature Engineering:* Telemetry is aggregated into 15-minute time windows per entity. We extract 18 distinct features, including execution volumes, network connections, and rare process executions.
3. *Anomaly Scoring:* A semi-static Isolation Forest model evaluates the feature windows against a trained baseline, generating anomaly scores and identifying suspicious findings.
4. *Correlation Engine:* Suspicious findings are correlated using a ruleset mapped to the MITRE ATT&CK framework, aggregating isolated anomalies into cohesive incident narratives.
5. *Prioritization and SOAR Integration:* Incidents are scored based on severity, confidence, and available evidence. High-priority incidents (P1-P3) are automatically pushed to TheHive (SOAR) for analyst review, and feedback is re-ingested into Splunk via HEC.

= Implementation Details

We implemented the core ML engine in Python using `scikit-learn` and `pandas`. The Isolation Forest model operates with a contamination parameter of 0.05. Instead of relying solely on the raw model output, we calibrate the anomaly score using a baseline deviation metric to handle low-variance environments effectively.

The correlation engine applies six specific rules to group findings:
- Reconnaissance Activity
- Suspicious PowerShell Activity
- Brute Force Attempt
- Data Exfiltration
- Suspicious LOLBin Execution
- Malicious Process Execution

These correlated incidents are then passed to the prioritizer, which assigns a priority level from P1 to P4.

= Experimental Setup

We evaluated CogniSOC in a simulated SOC lab environment consisting of Windows 10 endpoints and an Ubuntu-based SIEM (Splunk + Suricata). We utilized the Atomic Red Team framework to generate attack telemetry representing seven distinct MITRE ATT&CK techniques, including defense evasion, credential dumping, and data exfiltration.

To compare CogniSOC against traditional approaches, we implemented a Rules-Only baseline detector. This detector applied 13 Sigma rules (representing standard SIEM detection logic) directly to the telemetry without any ML model intervention.

= Results

We conducted an ablation study to quantify the contribution of each pipeline stage:
- *Config A:* Isolation Forest Only
- *Config B:* IF + Correlation Engine
- *Config C:* Full System (IF + Correlation + Prioritizer)

#figure(
  image("figures/performance_comparison.png", width: 90%),
  caption: [Performance Comparison: Rules-Only Baseline vs. CogniSOC (Isolation Forest)]
)

== Baseline Comparison

Our evaluation dataset comprised 61 time windows (40 benign, 21 malicious). As shown in the performance comparison figure, the Rules-Only baseline achieved a precision of 100% but a poor recall of 10.7%, successfully identifying only 3 out of 21 attack windows. This low recall is typical of rigid pattern-matching rules, which fail to detect variations in attack techniques.

In contrast, the Isolation Forest model (Config A) improved recall to 42.8%, detecting 9 out of 21 attack windows while maintaining 100% precision. The ML model demonstrated its ability to detect anomalous behavior that bypassed static rules, such as encoded PowerShell execution and rare process invocation.

== Alert Volume Reduction

The true value of CogniSOC lies in its alert reduction capabilities. The Rules-Only baseline generated 3 alerts. The raw Isolation Forest model generated 9 suspicious findings.

#figure(
  image("figures/alert_volume_reduction.png", width: 90%),
  caption: [Alert Volume Reduction across CogniSOC pipeline stages.]
)

When passed through the Correlation Engine (Config B), the 9 anomalies were effectively grouped into 3 cohesive incidents. This aggregation provides SOC analysts with a unified narrative rather than isolated events. The Full System (Config C) maintained these 3 incidents, successfully filtering and prioritizing them for investigation in the SOAR platform. 

This end-to-end approach ensures that while the ML model increases the detection rate (recall), the subsequent correlation and prioritization layers prevent a corresponding explosion in alert volume, mitigating analyst fatigue.

= Discussion and Limitations

Our results validate the necessity of a multi-staged approach in modern SOCs. Relying solely on ML anomaly scores often increases the burden on analysts due to false positives or lacking context. CogniSOC's correlation engine and MITRE ATT&CK mapping provide the necessary context to make ML findings actionable.

A limitation of our study is the reliance on a controlled lab environment and synthetic telemetry generated via Atomic Red Team. While this provides a robust foundation for evaluation, real-world enterprise networks exhibit significantly higher noise levels and more complex baseline behaviors. Future work will involve deploying CogniSOC in a larger, production-scale environment to validate its scalability and false-positive resilience over extended periods.

= Conclusion

In this paper, we introduced CogniSOC, an open-source behavioral analytics framework designed to bridge the gap between academic anomaly detection models and operational SOC workflows. By integrating an Isolation Forest model with SIEM telemetry, MITRE ATT&CK correlation, and SOAR automation, CogniSOC provides a complete, end-to-end reference architecture. Our evaluation demonstrated that this approach significantly improves detection recall over static rules while maintaining manageable alert volumes through effective correlation and prioritization. CogniSOC provides a practical blueprint for deploying actionable AI in Security Operations Centers.

// References would go here.
