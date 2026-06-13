# ================================================
# SOC ML Engine — Full Pipeline One-Shot Script
# Run AFTER attacks. Baseline training NOT included.
# ================================================

# --- EDIT THESE ONCE ---
$env:SPLUNK_HOST     = "172.16.140.130"
$env:SPLUNK_PORT     = "8089"
$env:SPLUNK_USERNAME = "ankit"
$env:SPLUNK_PASSWORD = "Ankitsingh1@"
$env:SPLUNK_INDEX    = "main"
$env:THEHIVE_URL     = "http://172.16.140.130:9000"
$env:THEHIVE_API_KEY = "l4bqx+qEl5LGL+ItsyGMqae8MIf0MwUo"
$HEC_URL             = "http://172.16.140.130:8088/services/collector"
$HEC_TOKEN           = "701df9de-49ca-4324-a6a8-1990c8672844"
$DETECT_WINDOW       = "-7d"   # How far back to look for attacks
# -----------------------

Write-Host "`n[1/5] Running ML Detection..." -ForegroundColor Cyan
python -m soc_ml_engine.main --config soc_ml_engine/config/soc_ml_config.example.json detect --earliest-time=$DETECT_WINDOW --latest-time=now --write-splunk-hec
if ($LASTEXITCODE -ne 0) { Write-Host "Detection failed! Stopping." -ForegroundColor Red; exit 1 }

Write-Host "`n[2/5] Running Correlation Pipeline..." -ForegroundColor Cyan
python -m soc_ml_engine.correlation.correlator
python -m soc_ml_engine.correlation.timeline_builder
python -m soc_ml_engine.correlation.prioritizer
python -m soc_ml_engine.correlation.report_generator

Write-Host "`n[3/5] Pushing Incidents to TheHive..." -ForegroundColor Cyan
python -m soc_ml_engine.integration.thehive_connector --mode cases

Write-Host "`n[4/5] Pushing Findings to Splunk HEC..." -ForegroundColor Cyan
python -m soc_ml_engine.integration.splunk_hec_push --hec-url $HEC_URL --hec-token $HEC_TOKEN

Write-Host "`n[5/5] Launching SOC Dashboard..." -ForegroundColor Cyan
Write-Host "  Python Dashboard: http://127.0.0.1:8050" -ForegroundColor Green
Write-Host "  Splunk Dashboard: http://172.16.140.130:8000 -> SOC Command Center" -ForegroundColor Green
python -m soc_ml_engine.dashboard --port 8050
