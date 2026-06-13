"""Local SOC operations dashboard for ML suspicious findings."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

from soc_ml_engine.dashboard_enhancements import enhance_dashboard_html


LOGGER = logging.getLogger("soc_ml_engine.dashboard")
DEFAULT_FINDINGS = Path("soc_ml_engine/outputs/suspicious_events.json")


def load_findings(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        LOGGER.warning("Findings file exists but is not valid JSON: %s", path)
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    entity_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    total_events = 0
    total_suricata_alerts = 0
    for item in findings:
        severity = str(item.get("severity", "low")).lower()
        counts[severity] = counts.get(severity, 0) + 1
        entity = str(item.get("host") or item.get("source_ip") or item.get("entity") or "unknown")
        event_type = str(item.get("event_type") or "unknown")
        entity_counts[entity] = entity_counts.get(entity, 0) + 1
        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        features = item.get("features", {})
        if isinstance(features, dict):
            total_events += int(float(features.get("event_count", 0) or 0))
            total_suricata_alerts += int(float(features.get("suricata_alert_count", 0) or 0))
    top_score = max((float(item.get("anomaly_score", 0.0)) for item in findings), default=0.0)
    return {
        "total": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "top_score": round(top_score, 2),
        "total_correlated_events": total_events,
        "suricata_alerts": total_suricata_alerts,
        "top_entity": _top_key(entity_counts),
        "top_event_type": _top_key(event_type_counts),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def make_handler(findings_path: Path) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(DASHBOARD_HTML)
                return
            if parsed.path == "/api/findings":
                params = parse_qs(parsed.query)
                minimum = float(params.get("min_score", ["0"])[0])
                findings = [
                    finding
                    for finding in load_findings(findings_path)
                    if float(finding.get("anomaly_score", 0.0)) >= minimum
                ]
                findings.sort(key=lambda item: float(item.get("anomaly_score", 0.0)), reverse=True)
                self._send_json(
                    {
                        "summary": summarize(findings),
                        "findings": findings,
                        "source_file": str(findings_path),
                    }
                )
                return
            self.send_error(404, "Not found")

        def log_message(self, format: str, *args: Any) -> None:
            LOGGER.info("%s - %s", self.address_string(), format % args)

        def _send_html(self, content: str) -> None:
            encoded = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _send_json(self, payload: dict[str, Any]) -> None:
            encoded = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return DashboardHandler


def _top_key(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[0][0]


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SOC Operations Dashboard</title>
  <style>
    :root {
      --bg: #eef2f6;
      --surface: #ffffff;
      --surface-2: #f7f9fb;
      --ink: #17202a;
      --muted: #607080;
      --line: #d7dee7;
      --line-strong: #b9c4d0;
      --accent: #155e75;
      --accent-2: #0f766e;
      --critical: #b42318;
      --high: #c2410c;
      --medium: #b7791f;
      --low: #3f7d20;
      --info: #2563eb;
      --shadow: 0 1px 2px rgba(15, 23, 42, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: "Segoe UI", Arial, sans-serif;
      font-size: 14px;
    }
    header {
      background: #111827;
      color: #fff;
      padding: 14px 22px;
      border-bottom: 3px solid var(--accent-2);
    }
    .header-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 650;
      letter-spacing: 0;
    }
    .subtitle {
      margin-top: 4px;
      color: #b6c2cf;
      font-size: 12px;
    }
    .header-status {
      display: flex;
      gap: 8px;
      align-items: center;
      color: #d9e2ec;
      font-size: 12px;
    }
    .live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #22c55e;
      display: inline-block;
    }
    main {
      width: min(1500px, calc(100vw - 28px));
      margin: 14px auto 28px;
    }
    .controls {
      display: grid;
      grid-template-columns: minmax(260px, 1fr) repeat(4, max-content);
      gap: 10px;
      align-items: end;
      margin-bottom: 12px;
    }
    label {
      color: var(--muted);
      display: block;
      font-size: 11px;
      font-weight: 650;
      margin-bottom: 5px;
      text-transform: uppercase;
    }
    input, select, button {
      width: 100%;
      border: 1px solid var(--line-strong);
      background: var(--surface);
      border-radius: 6px;
      padding: 8px 10px;
      color: var(--ink);
      font: inherit;
      min-height: 36px;
    }
    button {
      cursor: pointer;
      color: #fff;
      background: var(--accent);
      border-color: var(--accent);
      font-weight: 650;
      white-space: nowrap;
    }
    .secondary-button {
      background: var(--surface);
      color: var(--ink);
      border-color: var(--line-strong);
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(7, minmax(120px, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }
    .metric, .panel, .detail-panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .metric {
      padding: 12px;
      min-height: 82px;
    }
    .metric span {
      color: var(--muted);
      display: block;
      font-size: 11px;
      font-weight: 650;
      margin-bottom: 8px;
      text-transform: uppercase;
    }
    .metric strong {
      display: block;
      font-size: 25px;
      line-height: 1;
    }
    .metric small {
      color: var(--muted);
      display: block;
      margin-top: 8px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .scope-strip {
      animation: fadeIn .35s ease-out;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      display: grid;
      gap: 10px;
      grid-template-columns: 1.1fr 1fr 1fr;
      margin-bottom: 12px;
      padding: 12px;
    }
    .scope-item {
      border-left: 3px solid var(--accent-2);
      padding-left: 10px;
    }
    .scope-item strong {
      display: block;
      font-size: 13px;
      margin-bottom: 3px;
    }
    .scope-item span {
      color: var(--muted);
      font-size: 12px;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 420px;
      gap: 12px;
      align-items: start;
    }
    .left-stack {
      display: grid;
      gap: 12px;
      min-width: 0;
    }
    .chart-grid {
      display: grid;
      grid-template-columns: 260px 1fr 320px;
      gap: 12px;
    }
    .panel {
      min-height: 230px;
      padding: 12px;
      overflow: hidden;
    }
    .panel h2, .detail-panel h2 {
      margin: 0 0 10px;
      font-size: 14px;
      font-weight: 650;
      letter-spacing: 0;
    }
    canvas {
      width: 100%;
      height: 170px;
      display: block;
    }
    .table-panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .table-header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 12px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }
    .table-header h2 {
      margin: 0;
      font-size: 14px;
    }
    .table-wrap {
      overflow: auto;
      max-height: 540px;
    }
    table {
      border-collapse: collapse;
      min-width: 1060px;
      width: 100%;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f0f4f8;
      color: #2d3748;
      font-size: 11px;
      font-weight: 700;
      position: sticky;
      text-transform: uppercase;
      top: 0;
      white-space: nowrap;
      z-index: 1;
    }
    tr {
      cursor: pointer;
    }
    tbody tr:hover, tr.selected {
      background: #edf7f6;
    }
    .sev, .priority {
      display: inline-block;
      border-radius: 999px;
      color: #fff;
      font-weight: 700;
      padding: 4px 8px;
      min-width: 72px;
      text-align: center;
      text-transform: uppercase;
      font-size: 11px;
    }
    .priority {
      background: #334155;
      min-width: 38px;
    }
    .critical { background: var(--critical); }
    .high { background: var(--high); }
    .medium { background: var(--medium); }
    .low { background: var(--low); }
    .reason {
      min-width: 300px;
      max-width: 430px;
    }
    .muted { color: var(--muted); }
    .detail-panel {
      position: sticky;
      top: 12px;
      padding: 14px;
      max-height: calc(100vh - 28px);
      overflow: auto;
    }
    .detail-title {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: start;
      margin-bottom: 12px;
    }
    .detail-title strong {
      display: block;
      font-size: 16px;
      overflow-wrap: anywhere;
    }
    .section {
      border-top: 1px solid var(--line);
      padding-top: 12px;
      margin-top: 12px;
    }
    .kv {
      display: grid;
      grid-template-columns: 132px 1fr;
      gap: 7px 10px;
      font-size: 13px;
    }
    .kv span:nth-child(odd) {
      color: var(--muted);
    }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .chip {
      border: 1px solid var(--line);
      background: #f7fafc;
      border-radius: 999px;
      padding: 5px 8px;
      font-size: 12px;
    }
    .bar-row {
      display: grid;
      grid-template-columns: 150px 1fr 54px;
      gap: 8px;
      align-items: center;
      margin: 8px 0;
      font-size: 12px;
    }
    .bar-track {
      height: 8px;
      background: #e6ebf0;
      border-radius: 999px;
      overflow: hidden;
    }
    .bar {
      height: 100%;
      background: var(--accent-2);
      width: 0%;
      transition: width .45s ease;
    }
    .param-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }
    .param {
      background: var(--surface-2);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
    }
    .param span {
      color: var(--muted);
      display: block;
      font-size: 11px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .param strong {
      display: block;
      font-size: 16px;
      margin-top: 4px;
    }
    tr {
      animation: rowIn .22s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes rowIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    .action-list {
      margin: 0;
      padding-left: 18px;
    }
    .action-list li {
      margin: 6px 0;
    }
    .splunk-query {
      background: #0f172a;
      border-radius: 6px;
      color: #dbeafe;
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
      line-height: 1.4;
      padding: 10px;
      overflow-wrap: anywhere;
    }
    .empty {
      padding: 32px;
      color: var(--muted);
      text-align: center;
      border: 1px dashed var(--line-strong);
      border-radius: 8px;
      background: var(--surface);
    }
    @media (max-width: 1180px) {
      .grid, .chart-grid { grid-template-columns: 1fr; }
      .detail-panel { position: static; max-height: none; }
      .controls { grid-template-columns: 1fr 1fr; }
      .metrics { grid-template-columns: repeat(3, minmax(130px, 1fr)); }
      .scope-strip { grid-template-columns: 1fr; }
    }
    @media (max-width: 720px) {
      main { width: calc(100vw - 18px); }
      .controls, .metrics { grid-template-columns: 1fr; }
      header { padding: 13px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="header-row">
      <div>
        <h1>SOC Operations Dashboard</h1>
        <div class="subtitle">Behavioral analytics findings from Sysmon, Suricata, and Splunk</div>
      </div>
      <div class="header-status"><span class="live-dot"></span><span id="status">Loading</span></div>
    </div>
  </header>
  <main>
    <section class="controls" aria-label="Dashboard controls">
      <div>
        <label for="searchBox">Search entity, reason, process, or event type</label>
        <input id="searchBox" type="search" placeholder="Example: powershell, DESKTOP, flow, nslookup">
      </div>
      <div>
        <label for="minScore">Minimum score</label>
        <select id="minScore">
          <option value="0">All</option>
          <option value="90" selected>90+</option>
          <option value="97">97+</option>
          <option value="99">99+</option>
        </select>
      </div>
      <div>
        <label for="severityFilter">Severity</label>
        <select id="severityFilter">
          <option value="all">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      <div>
        <label for="sortBy">Sort</label>
        <select id="sortBy">
          <option value="score">Score</option>
          <option value="time">Newest</option>
          <option value="events">Event volume</option>
          <option value="entity">Entity</option>
        </select>
      </div>
      <div>
        <label>&nbsp;</label>
        <button id="refreshButton" type="button">Refresh</button>
      </div>
    </section>

    <section class="metrics" aria-label="SOC queue summary">
      <div class="metric"><span>Open Findings</span><strong id="mTotal">0</strong><small id="mFiltered">0 visible</small></div>
      <div class="metric"><span>Critical / High</span><strong id="mPriority">0</strong><small>Priority queue</small></div>
      <div class="metric"><span>Suricata Alerts</span><strong id="mSuricata">0</strong><small>Inside visible findings</small></div>
      <div class="metric"><span>Top Score</span><strong id="mTop">0</strong><small>Max anomaly score</small></div>
      <div class="metric"><span>Correlated Events</span><strong id="mEvents">0</strong><small>Across visible findings</small></div>
      <div class="metric"><span>Primary Entity</span><strong id="mEntity">-</strong><small>Most repeated host/source</small></div>
      <div class="metric"><span>Primary Event Type</span><strong id="mType">-</strong><small>Dominant telemetry class</small></div>
    </section>

    <section class="scope-strip" aria-label="Telemetry interpretation">
      <div class="scope-item">
        <strong>Aggregated Investigation View</strong>
        <span id="scopeAggregation">Raw logs are grouped into host/source-IP behavior windows.</span>
      </div>
      <div class="scope-item">
        <strong>Endpoint Coverage</strong>
        <span id="scopeEndpoint">Waiting for Sysmon-derived features.</span>
      </div>
      <div class="scope-item">
        <strong>Network Coverage</strong>
        <span id="scopeNetwork">Waiting for Suricata-derived features.</span>
      </div>
    </section>

    <section class="grid">
      <div class="left-stack">
        <section class="chart-grid">
          <div class="panel">
            <h2>Severity Distribution</h2>
            <canvas id="severityChart" width="300" height="180"></canvas>
          </div>
          <div class="panel">
            <h2>Findings Over Time</h2>
            <canvas id="timelineChart" width="620" height="180"></canvas>
          </div>
          <div class="panel">
            <h2>Top Entities</h2>
            <canvas id="entityChart" width="340" height="180"></canvas>
          </div>
        </section>

        <section class="table-panel">
          <div class="table-header">
            <h2>Investigation Queue</h2>
            <span class="muted" id="sourceFile">Waiting for findings file</span>
          </div>
          <div id="results" class="table-wrap"></div>
        </section>
      </div>

      <aside class="detail-panel" id="detailPanel">
        <div class="empty">Select a finding to review evidence, scoring, and triage actions.</div>
      </aside>
    </section>
  </main>

  <script>
    const statusEl = document.getElementById('status');
    const resultsEl = document.getElementById('results');
    const detailPanel = document.getElementById('detailPanel');
    const minScoreEl = document.getElementById('minScore');
    const severityFilterEl = document.getElementById('severityFilter');
    const sortByEl = document.getElementById('sortBy');
    const searchBox = document.getElementById('searchBox');
    const refreshButton = document.getElementById('refreshButton');
    const sourceFileEl = document.getElementById('sourceFile');
    let allFindings = [];
    let visibleFindings = [];
    let selectedId = null;

    function safe(value) {
      return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[char]));
    }

    function number(value) {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : 0;
    }

    function entity(item) {
      return item.host || item.source_ip || item.entity || 'unknown';
    }

    function findingId(item, index) {
      return `${item.timestamp || ''}|${entity(item)}|${item.event_type || ''}|${index}`;
    }

    function metric(id, value) {
      document.getElementById(id).textContent = value;
    }

    async function loadFindings() {
      const minScore = encodeURIComponent(minScoreEl.value);
      const response = await fetch(`/api/findings?min_score=${minScore}`, { cache: 'no-store' });
      const data = await response.json();
      sourceFileEl.textContent = data.source_file || '';
      allFindings = (data.findings || []).map((item, index) => ({ ...item, _id: findingId(item, index) }));
      applyFilters();
      statusEl.textContent = `Last refresh ${new Date().toLocaleTimeString()}`;
    }

    function applyFilters() {
      const term = searchBox.value.trim().toLowerCase();
      const severity = severityFilterEl.value;
      visibleFindings = allFindings.filter(item => {
        const haystack = JSON.stringify(item).toLowerCase();
        const severityMatch = severity === 'all' || String(item.severity || '').toLowerCase() === severity;
        const termMatch = !term || haystack.includes(term);
        return severityMatch && termMatch;
      });
      sortVisible();
      renderMetrics();
      renderCharts();
      renderTable();
      if (!visibleFindings.some(item => item._id === selectedId)) {
        selectedId = visibleFindings[0]?._id || null;
      }
      renderDetail(visibleFindings.find(item => item._id === selectedId));
    }

    function sortVisible() {
      const sortBy = sortByEl.value;
      visibleFindings.sort((a, b) => {
        if (sortBy === 'time') return new Date(b.timestamp || 0) - new Date(a.timestamp || 0);
        if (sortBy === 'events') return number(b.features?.event_count) - number(a.features?.event_count);
        if (sortBy === 'entity') return entity(a).localeCompare(entity(b));
        return number(b.anomaly_score) - number(a.anomaly_score);
      });
    }

    function renderMetrics() {
      const criticalHigh = visibleFindings.filter(item => ['critical', 'high'].includes(String(item.severity).toLowerCase())).length;
      const topScore = Math.max(0, ...visibleFindings.map(item => number(item.anomaly_score)));
      const totalEvents = visibleFindings.reduce((sum, item) => sum + number(item.features?.event_count), 0);
      const suricataAlerts = visibleFindings.reduce((sum, item) => sum + number(item.features?.suricata_alert_count), 0);
      const powershell = visibleFindings.reduce((sum, item) => sum + number(item.features?.powershell_count), 0);
      const cmd = visibleFindings.reduce((sum, item) => sum + number(item.features?.cmd_count), 0);
      const connections = visibleFindings.reduce((sum, item) => sum + number(item.features?.connection_count), 0);
      metric('mTotal', allFindings.length);
      metric('mFiltered', `${visibleFindings.length} visible`);
      metric('mPriority', criticalHigh);
      metric('mSuricata', suricataAlerts.toLocaleString());
      metric('mTop', topScore.toFixed(1));
      metric('mEvents', totalEvents.toLocaleString());
      metric('mEntity', topKey(visibleFindings.map(entity)) || '-');
      metric('mType', topKey(visibleFindings.map(item => item.event_type || 'unknown')) || '-');
      document.getElementById('scopeAggregation').textContent = `${totalEvents.toLocaleString()} raw logs collapsed into ${visibleFindings.length} investigation item(s).`;
      document.getElementById('scopeEndpoint').textContent = `${powershell.toLocaleString()} PowerShell events and ${cmd.toLocaleString()} cmd.exe events in visible findings.`;
      document.getElementById('scopeNetwork').textContent = `${connections.toLocaleString()} network connections and ${suricataAlerts.toLocaleString()} Suricata alerts in visible findings.`;
    }

    function topKey(values) {
      const counts = new Map();
      for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
      return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || '';
    }

    function countsBy(values) {
      const counts = new Map();
      for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
      return [...counts.entries()].sort((a, b) => b[1] - a[1]);
    }

    function renderCharts() {
      drawDonut(document.getElementById('severityChart'), countsBy(visibleFindings.map(item => String(item.severity || 'low').toLowerCase())));
      drawTimeline(document.getElementById('timelineChart'), visibleFindings);
      drawHorizontalBars(document.getElementById('entityChart'), countsBy(visibleFindings.map(entity)).slice(0, 6));
    }

    function setupCanvas(canvas) {
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.font = '12px Segoe UI, Arial';
      ctx.textBaseline = 'middle';
      return ctx;
    }

    function drawDonut(canvas, data) {
      const ctx = setupCanvas(canvas);
      const colors = { critical: '#b42318', high: '#c2410c', medium: '#b7791f', low: '#3f7d20' };
      const total = data.reduce((sum, item) => sum + item[1], 0);
      const cx = 82, cy = 82, radius = 58, inner = 34;
      if (!total) {
        ctx.fillStyle = '#607080';
        ctx.fillText('No findings', 92, 84);
        return;
      }
      let start = -Math.PI / 2;
      for (const [label, count] of data) {
        const angle = (count / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, radius, start, start + angle);
        ctx.closePath();
        ctx.fillStyle = colors[label] || '#64748b';
        ctx.fill();
        start += angle;
      }
      ctx.globalCompositeOperation = 'destination-out';
      ctx.beginPath();
      ctx.arc(cx, cy, inner, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalCompositeOperation = 'source-over';
      ctx.fillStyle = '#17202a';
      ctx.font = '700 22px Segoe UI, Arial';
      ctx.textAlign = 'center';
      ctx.fillText(total, cx, cy);
      ctx.textAlign = 'left';
      ctx.font = '12px Segoe UI, Arial';
      data.forEach(([label, count], index) => {
        const y = 36 + (index * 24);
        ctx.fillStyle = colors[label] || '#64748b';
        ctx.fillRect(170, y - 6, 10, 10);
        ctx.fillStyle = '#17202a';
        ctx.fillText(`${label.toUpperCase()} ${count}`, 188, y);
      });
    }

    function drawTimeline(canvas, findings) {
      const ctx = setupCanvas(canvas);
      const buckets = new Map();
      for (const item of findings) {
        const date = new Date(item.timestamp || 0);
        if (Number.isNaN(date.getTime())) continue;
        const key = date.toISOString().slice(0, 13).replace('T', ' ');
        buckets.set(key, (buckets.get(key) || 0) + 1);
      }
      const data = [...buckets.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-12);
      if (!data.length) {
        ctx.fillStyle = '#607080';
        ctx.fillText('No time buckets available', 20, 88);
        return;
      }
      const max = Math.max(...data.map(item => item[1]));
      const left = 34, bottom = 152, top = 18, width = canvas.width - 52;
      const barWidth = Math.max(12, width / data.length - 8);
      ctx.strokeStyle = '#d7dee7';
      ctx.beginPath();
      ctx.moveTo(left, top);
      ctx.lineTo(left, bottom);
      ctx.lineTo(canvas.width - 12, bottom);
      ctx.stroke();
      data.forEach(([label, count], index) => {
        const x = left + 8 + index * (width / data.length);
        const height = Math.max(4, (count / max) * (bottom - top - 8));
        ctx.fillStyle = '#155e75';
        ctx.fillRect(x, bottom - height, barWidth, height);
        ctx.fillStyle = '#607080';
        ctx.save();
        ctx.translate(x + 2, bottom + 12);
        ctx.rotate(-0.45);
        ctx.fillText(label.slice(5), 0, 0);
        ctx.restore();
      });
    }

    function drawHorizontalBars(canvas, data) {
      const ctx = setupCanvas(canvas);
      if (!data.length) {
        ctx.fillStyle = '#607080';
        ctx.fillText('No entities available', 18, 88);
        return;
      }
      const max = Math.max(...data.map(item => item[1]));
      data.forEach(([label, count], index) => {
        const y = 22 + index * 25;
        const width = Math.max(4, (count / max) * (canvas.width - 130));
        ctx.fillStyle = '#607080';
        ctx.fillText(String(label).slice(0, 18), 8, y);
        ctx.fillStyle = '#0f766e';
        ctx.fillRect(126, y - 7, width, 12);
        ctx.fillStyle = '#17202a';
        ctx.fillText(count, 132 + width, y);
      });
    }

    function renderTable() {
      if (!visibleFindings.length) {
        resultsEl.innerHTML = '<div class="empty">No findings match the current filters.</div>';
        return;
      }
      const rows = visibleFindings.map(item => {
        const severity = safe(String(item.severity || 'low').toLowerCase());
        const features = item.features || {};
        const selected = item._id === selectedId ? ' selected' : '';
        return `<tr class="${selected}" data-id="${safe(item._id)}">
          <td><span class="priority">${safe(item.priority || 'P3')}</span></td>
          <td><span class="sev ${severity}">${severity}</span></td>
          <td><strong>${safe(item.anomaly_score)}</strong><div class="muted">${safe(item.confidence || 'medium')} confidence</div></td>
          <td>${safe(item.timestamp)}</td>
          <td>${safe(entity(item))}</td>
          <td>${safe(item.event_type)}</td>
          <td class="reason">${safe(item.reason)}</td>
          <td>${safe(features.event_count || 0)}</td>
          <td>${safe(features.powershell_count || 0)}</td>
          <td>${safe(features.cmd_count || 0)}</td>
          <td>${safe(features.connection_count || 0)}</td>
          <td>${safe(features.suricata_alert_count || 0)}</td>
          <td>${safe(features.unique_dest_ports || 0)}</td>
        </tr>`;
      }).join('');
      resultsEl.innerHTML = `<table>
        <thead>
          <tr>
            <th>Priority</th>
            <th>Severity</th>
            <th>Score</th>
            <th>Time</th>
            <th>Entity</th>
            <th>Event Type</th>
            <th>Reason</th>
            <th>Events</th>
            <th>PowerShell</th>
            <th>cmd.exe</th>
            <th>Connections</th>
            <th>Suricata</th>
            <th>Ports</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
      resultsEl.querySelectorAll('tr[data-id]').forEach(row => {
        row.addEventListener('click', () => {
          selectedId = row.getAttribute('data-id');
          renderTable();
          renderDetail(visibleFindings.find(item => item._id === selectedId));
        });
      });
    }

    function renderDetail(item) {
      if (!item) {
        detailPanel.innerHTML = '<div class="empty">Select a finding to review evidence, scoring, and triage actions.</div>';
        return;
      }
      const severity = safe(String(item.severity || 'low').toLowerCase());
      const features = item.features || {};
      const scoreComponents = item.score_components || {};
      const rareProcesses = item.rare_processes || [];
      const parentPairs = item.unexpected_parent_child_pairs || [];
      const riskFactors = item.risk_factors || [];
      const mitre = item.mitre_context || [];
      const actions = item.recommended_actions || [];
      detailPanel.innerHTML = `
        <div class="detail-title">
          <div>
            <strong>${safe(entity(item))}</strong>
            <div class="muted">${safe(item.timestamp)}</div>
          </div>
          <span class="sev ${severity}">${severity}</span>
        </div>
        <div class="kv">
          <span>Priority</span><strong>${safe(item.priority || 'P3')}</strong>
          <span>Score</span><strong>${safe(item.anomaly_score)} / 100</strong>
          <span>Confidence</span><strong>${safe(item.confidence || 'medium')}</strong>
          <span>Event type</span><strong>${safe(item.event_type)}</strong>
          <span>Host</span><strong>${safe(item.host || '-')}</strong>
          <span>Source IP</span><strong>${safe(item.source_ip || '-')}</strong>
        </div>
        <div class="section">
          <h2>Why It Fired</h2>
          <p>${safe(item.reason)}</p>
          <div class="chips">${riskFactors.map(value => `<span class="chip">${safe(value)}</span>`).join('') || '<span class="muted">No explicit risk factors listed.</span>'}</div>
        </div>
        <div class="section">
          <h2>Score Components</h2>
          ${scoreBar('Isolation Forest percentile', scoreComponents.isolation_forest_percentile)}
          ${scoreBar('Baseline deviation', scoreComponents.baseline_deviation_score)}
          <div class="muted">Raw model score: ${safe(scoreComponents.raw_model_score ?? 'n/a')}</div>
        </div>
        <div class="section">
          <h2>Telemetry Evidence</h2>
          <div class="kv">
            <span>Total events</span><strong>${safe(features.event_count || 0)}</strong>
            <span>PowerShell</span><strong>${safe(features.powershell_count || 0)}</strong>
            <span>cmd.exe</span><strong>${safe(features.cmd_count || 0)}</strong>
            <span>Connections</span><strong>${safe(features.connection_count || 0)}</strong>
            <span>Unique ports</span><strong>${safe(features.unique_dest_ports || 0)}</strong>
            <span>Rare processes</span><strong>${safe(features.rare_process_count || 0)}</strong>
            <span>Suricata alerts</span><strong>${safe(features.suricata_alert_count || 0)}</strong>
            <span>Event types</span><strong>${eventTypeSummary(features)}</strong>
          </div>
        </div>
        <div class="section">
          <h2>All Model Parameters</h2>
          <div class="param-grid">${renderFeatureParams(features)}</div>
        </div>
        <div class="section">
          <h2>Rare Processes</h2>
          <div class="chips">${rareProcesses.map(value => `<span class="chip">${safe(value)}</span>`).join('') || '<span class="muted">None listed.</span>'}</div>
        </div>
        <div class="section">
          <h2>Process Lineage</h2>
          <div class="chips">${parentPairs.map(value => `<span class="chip">${safe(value)}</span>`).join('') || '<span class="muted">No unexpected parent-child pairs listed.</span>'}</div>
        </div>
        <div class="section">
          <h2>ATT&CK Context</h2>
          <div class="chips">${mitre.map(value => `<span class="chip">${safe(value)}</span>`).join('') || '<span class="muted">No mapped context.</span>'}</div>
        </div>
        <div class="section">
          <h2>Analyst Actions</h2>
          <ol class="action-list">${actions.map(value => `<li>${safe(value)}</li>`).join('') || '<li>Review source telemetry in Splunk.</li>'}</ol>
        </div>
        <div class="section">
          <h2>Splunk Pivot</h2>
          <div class="splunk-query">${safe(buildSplunkQuery(item))}</div>
        </div>`;
    }

    function scoreBar(label, value) {
      const width = Math.max(0, Math.min(100, number(value)));
      return `<div class="bar-row">
        <span>${safe(label)}</span>
        <div class="bar-track"><div class="bar" style="width:${width}%"></div></div>
        <strong>${width.toFixed(1)}</strong>
      </div>`;
    }

    function renderFeatureParams(features) {
      const preferredOrder = [
        'event_count',
        'process_event_count',
        'network_event_count',
        'suricata_alert_count',
        'powershell_count',
        'cmd_count',
        'unique_process_count',
        'top_process_frequency',
        'unique_dest_ports',
        'connection_count',
        'unique_parent_child_pairs',
        'rare_process_count',
        'unexpected_parent_child_count',
        'event_type_process_create',
        'event_type_network_connection',
        'event_type_suricata_alert',
        'event_type_dns_query',
        'event_type_file_created',
        'event_type_other'
      ];
      const keys = [...new Set([...preferredOrder, ...Object.keys(features || {})])];
      return keys.map(key => `<div class="param"><span>${safe(labelize(key))}</span><strong>${safe(features?.[key] ?? 0)}</strong></div>`).join('');
    }

    function eventTypeSummary(features) {
      const parts = [
        ['process', features.event_type_process_create],
        ['network', features.event_type_network_connection],
        ['suricata', features.event_type_suricata_alert],
        ['dns', features.event_type_dns_query],
        ['file', features.event_type_file_created],
        ['other', features.event_type_other]
      ].filter(item => number(item[1]) > 0);
      return parts.length ? parts.map(item => `${item[0]}:${item[1]}`).join(' ') : 'none';
    }

    function labelize(value) {
      return String(value).replaceAll('_', ' ');
    }

    function buildSplunkQuery(item) {
      const host = item.host ? `host="${item.host}"` : '';
      const sourceIp = item.source_ip ? `(SourceIp="${item.source_ip}" OR src_ip="${item.source_ip}")` : '';
      const entityClause = [host, sourceIp].filter(Boolean).join(' OR ') || `host="${entity(item)}"`;
      const timestamp = item.timestamp ? new Date(item.timestamp) : null;
      let earliest = '-24h';
      let latest = 'now';
      if (timestamp && !Number.isNaN(timestamp.getTime())) {
        earliest = new Date(timestamp.getTime() - 15 * 60 * 1000).toISOString();
        latest = new Date(timestamp.getTime() + 30 * 60 * 1000).toISOString();
      }
      return `index=main (${entityClause}) earliest="${earliest}" latest="${latest}" | table _time host sourcetype EventID Image ParentImage CommandLine SourceIp DestinationIp DestinationPort event_type signature _raw`;
    }

    refreshButton.addEventListener('click', loadFindings);
    minScoreEl.addEventListener('change', loadFindings);
    severityFilterEl.addEventListener('change', applyFilters);
    sortByEl.addEventListener('change', applyFilters);
    searchBox.addEventListener('input', applyFilters);
    loadFindings().catch(error => {
      statusEl.textContent = `Dashboard error: ${error}`;
    });
    setInterval(() => loadFindings().catch(() => {}), 30000);
  </script>
</body>
</html>
"""

DASHBOARD_HTML = enhance_dashboard_html(DASHBOARD_HTML)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the SOC ML findings dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8050)
    parser.add_argument("--findings-file", type=Path, default=DEFAULT_FINDINGS)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")
    handler = make_handler(args.findings_file)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"SOC ML dashboard: http://{args.host}:{args.port}")
    print(f"Reading findings from: {args.findings_file}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
