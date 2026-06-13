# SOC ML Engine

Python behavioral analytics module for the existing SOC lab. Splunk remains the SIEM and rule-based detection layer; this module adds explainable anomaly scoring over recent Sysmon and Suricata telemetry.

## What it does

- Pulls recent events from Splunk Enterprise through the REST API.
- Normalizes Sysmon and Suricata fields, including raw Sysmon XML and Suricata EVE JSON where available.
- Aggregates telemetry into host/source-IP time windows.
- Extracts explainable features such as PowerShell frequency, cmd.exe frequency, destination port diversity, connection count, parent-child process relationships, event-type distribution, and rare processes.
- Trains a semi-static Isolation Forest baseline from known-normal lab telemetry.
- Scores later telemetry without retraining on every pass.
- Writes suspicious findings as JSON and can also prepare Splunk HEC-ready NDJSON for re-ingestion.

## Install

Use Python 3.11.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Configure Splunk

Keep credentials in environment variables. The example config stores only non-secret defaults.

```powershell
$env:SPLUNK_HOST = "192.168.56.20"
$env:SPLUNK_PORT = "8089"
$env:SPLUNK_USERNAME = "admin"
$env:SPLUNK_PASSWORD = "<your password>"
$env:SPLUNK_INDEX = "main"
```

Token auth is also supported:

```powershell
$env:SPLUNK_TOKEN = "<splunk bearer token>"
```

The default REST endpoint is `https://<host>:8089`. SSL verification defaults to `false` because Splunk lab instances often use a self-signed certificate. Set `SPLUNK_VERIFY_SSL=true` when using a trusted certificate.

## Train a baseline

Collect a normal period of lab activity first. Do not include Atomic Red Team attack simulations in the baseline window.

```powershell
python -m soc_ml_engine.main --config soc_ml_engine/config/soc_ml_config.example.json baseline --earliest-time -24h --latest-time now
```

For offline validation with bundled sample telemetry, use the validation harness below. It trains only on records marked as baseline and then scores the full sample.

## Run detection

Score a recent time range once:

```powershell
python -m soc_ml_engine.main --config soc_ml_engine/config/soc_ml_config.example.json detect --earliest-time -30m --latest-time now
```

Run scheduled scoring every 15 minutes:

```powershell
python -m soc_ml_engine.main --config soc_ml_engine/config/soc_ml_config.example.json detect --loop --interval-seconds 900
```

For near-real-time lab monitoring, run the detector and dashboard together:

```powershell
python -m soc_ml_engine.realtime --score-window=-2h --interval-seconds 60 --max-events 20000 --min-score 90 --write-splunk-hec --dashboard-port 8050
```

This scores a rolling Splunk window every 60 seconds, writes `soc_ml_engine/outputs/suspicious_events.json`, and serves the dashboard at `http://127.0.0.1:8050`.

Prepare findings for Splunk HEC-style re-ingestion:

```powershell
python -m soc_ml_engine.main detect --write-splunk-hec
```

Output files default to:

- `soc_ml_engine/outputs/suspicious_events.json`
- `soc_ml_engine/outputs/splunk_hec_events.ndjson`
- `soc_ml_engine/outputs/isolation_forest_model.pkl`

## View the dashboard

After running detection, start the local findings dashboard:

```powershell
python -m soc_ml_engine.dashboard --port 8050
```

Open:

```text
http://127.0.0.1:8050
```

The dashboard reads `soc_ml_engine/outputs/suspicious_events.json` and refreshes every 30 seconds.

The dashboard includes an investigation queue, severity distribution, timeline, top entities, score components, risk factors, rare processes, ATT&CK-style context, recommended analyst actions, and a Splunk pivot query for the selected finding.

## Baseline schedule

Do not retrain the model every minute. Train it from known-normal lab telemetry, then continuously score new telemetry.

Recommended lab workflow:

- Train baseline after collecting normal activity, before running Atomic Red Team or attack simulations.
- Retrain only when the lab changes materially, such as new endpoint software, new Sysmon config, new Suricata visibility, or after a clean new normal period.
- For a college SOC lab, weekly retraining or manual retraining before a demo is enough.
- Run `soc_ml_engine.realtime` during attack simulation so new Splunk events are fetched and scored automatically.

## Validate locally

The validation harness trains on benign sample telemetry, scores benign plus suspicious sample telemetry, and writes example findings.

```powershell
python -m soc_ml_engine.tests.validate_sample
Get-Content soc_ml_engine/outputs/validation_findings.json
```

## Feature design

The model scores aggregated behavior per entity and time window, not isolated raw log lines. This makes the result closer to how a SOC analyst thinks: "this host behaved strangely during this interval." Raw events still inform the reason field through rare process names and unexpected parent-child pairs.

Features are numeric counts so they stay explainable in a viva or SOC engineering review. A `StandardScaler` is fitted during baseline training and reused during detection. Isolation Forest is not a distance-only model, but scaling keeps large-count features from dominating split behavior and makes feature comparison more stable across lab runs.

The final anomaly score uses the Isolation Forest baseline score plus a narrow baseline-deviation calibration for very small lab baselines. This prevents a low-variance baseline from hiding obvious out-of-baseline behavior such as PowerShell execution, rare processes, unexpected parent-child process chains, or new Suricata alert activity.

## Assumptions

- Splunk index `main` contains Sysmon and Suricata telemetry.
- Sysmon process creation is Event ID `1`; network connection is Event ID `3`.
- Suricata EVE JSON may be present in `_raw`, but direct Splunk fields such as `src_ip`, `dest_ip`, and `dest_port` are also supported.
- The baseline period represents normal lab behavior.
- ML findings augment Splunk detections; they are not a replacement for correlation searches, alerts, dashboards, or analyst validation.

## Practical next improvements

- Add a Splunk saved search or scheduled task wrapper around detection mode.
- Send HEC output directly to Splunk after creating a dedicated sourcetype such as `soc:ml:anomaly`.
- Enrich findings with MITRE technique tags from Atomic Red Team validation metadata.
- Add dashboard panels in Splunk for anomaly score trends by host and source IP.
