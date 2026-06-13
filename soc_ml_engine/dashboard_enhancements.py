ADVANCED_DASHBOARD_STYLE = r"""
<style>
  :root {
    --bg: #050b18;
    --surface: rgba(10, 20, 38, .86);
    --surface-2: rgba(15, 28, 50, .92);
    --ink: #e5efff;
    --muted: #91a7c5;
    --line: rgba(125, 211, 252, .18);
    --line-strong: rgba(125, 211, 252, .34);
    --accent: #38bdf8;
    --accent-2: #22d3ee;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --info: #60a5fa;
    --shadow: 0 18px 50px rgba(0, 0, 0, .34);
  }
  body {
    background: radial-gradient(circle at top left, rgba(56, 189, 248, .22), transparent 34%), radial-gradient(circle at 78% 4%, rgba(124, 58, 237, .18), transparent 28%), linear-gradient(135deg, #050b18 0%, #071426 46%, #06111f 100%);
    min-height: 100vh;
    overflow-x: hidden;
  }
  body::before {
    animation: advDrift 18s linear infinite;
    background-image: linear-gradient(rgba(125, 211, 252, .06) 1px, transparent 1px), linear-gradient(90deg, rgba(125, 211, 252, .05) 1px, transparent 1px);
    background-size: 42px 42px;
    content: "";
    inset: 0;
    pointer-events: none;
    position: fixed;
    z-index: -1;
  }
  header {
    background: rgba(3, 7, 18, .78);
    backdrop-filter: blur(18px);
    border-bottom: 1px solid rgba(34, 211, 238, .3);
    box-shadow: 0 12px 44px rgba(0, 0, 0, .35);
  }
  h1, .panel h2, .detail-panel h2, .table-header h2 { color: #f8fbff; }
  input, select, button {
    background: rgba(8, 18, 35, .88);
    border-color: rgba(148, 163, 184, .32);
    color: #e5efff;
  }
  button { background: linear-gradient(135deg, #0284c7, #0891b2); box-shadow: 0 10px 28px rgba(14, 165, 233, .24); }
  .metric, .panel, .detail-panel, .table-panel, .scope-strip {
    background: rgba(8, 18, 35, .72);
    backdrop-filter: blur(18px);
    border-color: rgba(125, 211, 252, .18);
    box-shadow: var(--shadow);
  }
  .metric { overflow: hidden; position: relative; }
  .metric::after {
    animation: advSweep 4.8s ease-in-out infinite;
    background: linear-gradient(90deg, transparent, rgba(125, 211, 252, .16), transparent);
    content: "";
    height: 100%;
    left: -80%;
    position: absolute;
    top: 0;
    width: 60%;
  }
  th { background: rgba(15, 23, 42, .98); color: #bfdbfe; }
  td { color: #dbeafe; }
  tbody tr:hover, tr.selected { background: rgba(14, 165, 233, .13); }
  .muted, label, .metric span, .metric small, .scope-item span, .param span { color: var(--muted); }
  .adv-hero {
    animation: advRise .55s ease-out both;
    background: linear-gradient(135deg, rgba(14, 165, 233, .22), rgba(15, 23, 42, .82) 42%, rgba(124, 58, 237, .2));
    border: 1px solid rgba(125, 211, 252, .24);
    border-radius: 22px;
    box-shadow: var(--shadow);
    display: grid;
    gap: 18px;
    grid-template-columns: 1.4fr .9fr;
    margin-bottom: 14px;
    overflow: hidden;
    padding: 20px;
    position: relative;
  }
  .adv-hero::before {
    animation: advGlow 7s ease-in-out infinite alternate;
    background: radial-gradient(circle, rgba(34, 211, 238, .28), transparent 58%);
    content: "";
    height: 260px;
    position: absolute;
    right: -90px;
    top: -110px;
    width: 260px;
  }
  .adv-eyebrow { color: #67e8f9; font-size: 12px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
  .adv-title { color: #f8fbff; font-size: clamp(28px, 4vw, 46px); font-weight: 850; letter-spacing: -.04em; line-height: .98; margin: 8px 0; }
  .adv-copy { color: #bad2f0; line-height: 1.55; max-width: 780px; }
  .adv-badges { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
  .adv-badge { background: rgba(15, 23, 42, .72); border: 1px solid rgba(125, 211, 252, .24); border-radius: 999px; color: #dbeafe; padding: 7px 10px; }
  .adv-ops-card { align-self: stretch; background: rgba(3, 7, 18, .5); border: 1px solid rgba(125, 211, 252, .18); border-radius: 18px; display: grid; gap: 12px; padding: 14px; position: relative; z-index: 1; }
  .adv-status-row { align-items: center; display: flex; justify-content: space-between; gap: 10px; }
  .adv-status-pill { animation: advPulse 1.8s ease-in-out infinite; background: rgba(34, 197, 94, .14); border: 1px solid rgba(34, 197, 94, .38); border-radius: 999px; color: #86efac; padding: 7px 10px; }
  .adv-ring-wrap { align-items: center; display: grid; gap: 16px; grid-template-columns: 128px 1fr; }
  .adv-ring { align-items: center; background: conic-gradient(#22d3ee var(--risk, 0%), rgba(51, 65, 85, .72) 0); border-radius: 50%; display: grid; height: 128px; justify-items: center; position: relative; width: 128px; }
  .adv-ring::after { background: #071426; border-radius: 50%; content: ""; inset: 12px; position: absolute; }
  .adv-ring strong { color: #f8fbff; font-size: 28px; position: relative; z-index: 1; }
  .adv-grid { display: grid; gap: 12px; grid-template-columns: repeat(6, minmax(130px, 1fr)); margin-bottom: 14px; }
  .adv-tile, .adv-panel {
    animation: advRise .55s ease-out both;
    background: rgba(8, 18, 35, .76);
    border: 1px solid rgba(125, 211, 252, .18);
    border-radius: 18px;
    box-shadow: var(--shadow);
    overflow: hidden;
    padding: 14px;
    position: relative;
  }
  .adv-tile strong { color: #f8fbff; display: block; font-size: 25px; margin-top: 8px; }
  .adv-tile span, .adv-panel-subtitle { color: var(--muted); font-size: 12px; }
  .adv-layout { display: grid; gap: 12px; grid-template-columns: 1.15fr .85fr .85fr; margin-bottom: 14px; }
  .adv-panel h2 { align-items: center; display: flex; font-size: 14px; gap: 8px; justify-content: space-between; margin: 0 0 10px; }
  .adv-list { display: grid; gap: 8px; }
  .adv-row { align-items: center; background: rgba(15, 23, 42, .56); border: 1px solid rgba(148, 163, 184, .16); border-radius: 12px; display: grid; gap: 8px; grid-template-columns: 1fr auto; padding: 9px 10px; }
  .adv-row small { color: var(--muted); display: block; margin-top: 3px; }
  .adv-score { border-radius: 999px; color: #020617; font-weight: 800; padding: 5px 8px; }
  .adv-score.critical { background: #fecaca; }
  .adv-score.high { background: #fed7aa; }
  .adv-score.medium { background: #fef08a; }
  .adv-score.low { background: #bbf7d0; }
  .adv-heatmap { display: grid; gap: 8px; grid-template-columns: repeat(5, minmax(80px, 1fr)); }
  .adv-cell { background: rgba(15, 23, 42, .66); border: 1px solid rgba(125, 211, 252, .14); border-radius: 13px; min-height: 72px; padding: 9px; }
  .adv-cell strong { color: #f8fbff; display: block; font-size: 22px; }
  .adv-cell span { color: var(--muted); display: block; font-size: 11px; margin-top: 4px; }
  .adv-lanes { display: grid; gap: 8px; }
  .adv-lane { background: rgba(15, 23, 42, .58); border-radius: 999px; overflow: hidden; position: relative; }
  .adv-lane div { background: linear-gradient(90deg, #38bdf8, #a78bfa); border-radius: inherit; height: 11px; min-width: 4%; transition: width .55s ease; }
  .adv-lane span { color: #cbd5e1; display: flex; font-size: 12px; justify-content: space-between; margin-bottom: 5px; }
  .adv-param-grid { display: grid; gap: 8px; grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .adv-param { background: rgba(15, 23, 42, .58); border: 1px solid rgba(148, 163, 184, .14); border-radius: 12px; padding: 9px; }
  .adv-param span { color: var(--muted); display: block; font-size: 11px; text-transform: uppercase; }
  .adv-param strong { color: #f8fbff; display: block; font-size: 18px; margin-top: 5px; }
  .adv-signal { display: grid; gap: 8px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .adv-signal-card { background: rgba(15, 23, 42, .58); border-left: 3px solid #38bdf8; border-radius: 12px; padding: 10px; }
  .adv-signal-card strong { color: #f8fbff; display: block; }
  .adv-signal-card span { color: var(--muted); font-size: 12px; }
  @keyframes advDrift { from { transform: translate3d(0, 0, 0); } to { transform: translate3d(42px, 42px, 0); } }
  @keyframes advSweep { 0%, 45% { transform: translateX(0); } 100% { transform: translateX(320%); } }
  @keyframes advRise { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes advPulse { 0%, 100% { box-shadow: 0 0 0 rgba(34, 197, 94, 0); } 50% { box-shadow: 0 0 24px rgba(34, 197, 94, .34); } }
  @keyframes advGlow { from { transform: scale(.9); } to { transform: scale(1.16); } }
  @media (max-width: 1280px) { .adv-layout { grid-template-columns: 1fr; } .adv-grid { grid-template-columns: repeat(3, minmax(130px, 1fr)); } .adv-hero { grid-template-columns: 1fr; } }
  @media (max-width: 760px) { .adv-grid, .adv-param-grid, .adv-heatmap, .adv-signal { grid-template-columns: 1fr; } .adv-ring-wrap { grid-template-columns: 1fr; } }
</style>
"""

ADVANCED_DASHBOARD_MARKUP = r"""
<section class="adv-hero" aria-label="SOC command center overview">
  <div>
    <div class="adv-eyebrow">Enterprise SOC anomaly command center</div>
    <div class="adv-title">Behavioral Threat Operations</div>
    <div class="adv-copy">Live anomaly detection workspace for endpoint, network, process lineage, command execution, model confidence, analyst triage, and Splunk pivot workflows.</div>
    <div class="adv-badges">
      <span class="adv-badge">Isolation Forest baseline</span>
      <span class="adv-badge">Sysmon process telemetry</span>
      <span class="adv-badge">Suricata network telemetry</span>
      <span class="adv-badge">Analyst-ready evidence</span>
    </div>
  </div>
  <div class="adv-ops-card">
    <div class="adv-status-row"><strong>Operations posture</strong><span class="adv-status-pill" id="advPosture">Standby</span></div>
    <div class="adv-ring-wrap">
      <div class="adv-ring" id="advThreatRing"><strong id="advThreatScore">0</strong></div>
      <div>
        <div class="adv-row"><span>Queue health<small id="advSource">Waiting for telemetry file</small></span><strong id="advQueueHealth">Normal</strong></div>
        <div class="adv-row"><span>Refresh cadence<small>Dashboard auto-refresh interval</small></span><strong>30s</strong></div>
      </div>
    </div>
  </div>
</section>
<section class="adv-grid" aria-label="SOC operations metrics">
  <div class="adv-tile"><span>Active findings</span><strong id="advOpenFindings">0</strong><small class="muted">Visible anomaly items</small></div>
  <div class="adv-tile"><span>P1/P2 pressure</span><strong id="advPriorityPressure">0</strong><small class="muted">Critical and high findings</small></div>
  <div class="adv-tile"><span>Endpoint signals</span><strong id="advEndpointSignals">0</strong><small class="muted">PowerShell, cmd, lineage</small></div>
  <div class="adv-tile"><span>Network signals</span><strong id="advNetworkSignals">0</strong><small class="muted">Connections, ports, IDS</small></div>
  <div class="adv-tile"><span>Rare behavior</span><strong id="advRareSignals">0</strong><small class="muted">Rare processes and lineage</small></div>
  <div class="adv-tile"><span>Confidence index</span><strong id="advConfidenceIndex">0%</strong><small class="muted">High confidence ratio</small></div>
</section>
<section class="adv-layout" aria-label="Advanced SOC dashboard panels">
  <div class="adv-panel">
    <h2>Attack Tactic Intelligence <span class="adv-panel-subtitle">Mapped from evidence</span></h2>
    <div class="adv-lanes" id="advTacticLanes"></div>
  </div>
  <div class="adv-panel">
    <h2>Entity Risk Ranking <span class="adv-panel-subtitle">Top assets</span></h2>
    <div class="adv-list" id="advEntityRisk"></div>
  </div>
  <div class="adv-panel">
    <h2>Live Alert Stream <span class="adv-panel-subtitle">Newest first</span></h2>
    <div class="adv-list" id="advAlertStream"></div>
  </div>
  <div class="adv-panel">
    <h2>Severity and Telemetry Heatmap <span class="adv-panel-subtitle">SOC load</span></h2>
    <div class="adv-heatmap" id="advHeatmap"></div>
  </div>
  <div class="adv-panel">
    <h2>Model Parameter Observatory <span class="adv-panel-subtitle">Feature pressure</span></h2>
    <div class="adv-param-grid" id="advModelParams"></div>
  </div>
  <div class="adv-panel">
    <h2>Analyst Decision Matrix <span class="adv-panel-subtitle">Suggested focus</span></h2>
    <div class="adv-signal" id="advDecisionMatrix"></div>
  </div>
</section>
"""

ADVANCED_DASHBOARD_SCRIPT = r"""
<script>
  (() => {
    const state = { findings: [], sourceFile: '' };
    const featureKeys = ['event_count', 'process_event_count', 'network_event_count', 'suricata_alert_count', 'powershell_count', 'cmd_count', 'unique_dest_ports', 'connection_count', 'rare_process_count', 'unexpected_parent_child_count', 'encoded_command_count', 'download_command_count', 'lolbin_count', 'suspicious_parent_child_count', 'external_connection_count', 'high_risk_process_count'];
    const tacticMap = [
      ['Execution', ['powershell_count', 'cmd_count', 'encoded_command_count', 'high_risk_process_count']],
      ['Defense Evasion', ['lolbin_count', 'suspicious_parent_child_count', 'unexpected_parent_child_count']],
      ['Discovery', ['unique_dest_ports', 'connection_count', 'dns_query_count']],
      ['Command Control', ['external_connection_count', 'suricata_alert_count', 'download_command_count']],
      ['Collection Impact', ['file_create_count', 'rare_process_count']]
    ];
    function byId(id) { return document.getElementById(id); }
    function value(path, fallback = 0) { const parsed = Number(path); return Number.isFinite(parsed) ? parsed : fallback; }
    function features(item) { return item.features && typeof item.features === 'object' ? item.features : {}; }
    function entity(item) { return item.host || item.source_ip || item.entity || 'unknown'; }
    function severityClass(score) { if (score >= 99) return 'critical'; if (score >= 97) return 'high'; if (score >= 90) return 'medium'; return 'low'; }
    function filteredFindings() {
      const minScore = value(byId('minScore')?.value, 0);
      const severity = byId('severityFilter')?.value || 'all';
      const term = String(byId('searchBox')?.value || '').trim().toLowerCase();
      return state.findings.filter(item => {
        const scoreMatch = value(item.anomaly_score) >= minScore;
        const sevMatch = severity === 'all' || String(item.severity || '').toLowerCase() === severity;
        const termMatch = !term || JSON.stringify(item).toLowerCase().includes(term);
        return scoreMatch && sevMatch && termMatch;
      });
    }
    async function refreshAdvanced() {
      try {
        const response = await fetch('/api/findings?min_score=0', { cache: 'no-store' });
        const data = await response.json();
        state.findings = Array.isArray(data.findings) ? data.findings : [];
        state.sourceFile = data.source_file || '';
        renderAdvanced(filteredFindings());
      } catch (error) {
        const posture = byId('advPosture');
        if (posture) posture.textContent = 'API error';
      }
    }
    function sum(findings, key) { return findings.reduce((total, item) => total + value(features(item)[key]), 0); }
    function renderAdvanced(findings) {
      const topScore = Math.max(0, ...findings.map(item => value(item.anomaly_score)));
      const p12 = findings.filter(item => value(item.anomaly_score) >= 97).length;
      const endpoint = sum(findings, 'powershell_count') + sum(findings, 'cmd_count') + sum(findings, 'unexpected_parent_child_count') + sum(findings, 'suspicious_parent_child_count');
      const network = sum(findings, 'connection_count') + sum(findings, 'unique_dest_ports') + sum(findings, 'suricata_alert_count') + sum(findings, 'external_connection_count');
      const rare = sum(findings, 'rare_process_count') + sum(findings, 'lolbin_count') + sum(findings, 'high_risk_process_count');
      const highConfidence = findings.filter(item => String(item.confidence || '').toLowerCase() === 'high').length;
      setText('advOpenFindings', findings.length.toLocaleString());
      setText('advPriorityPressure', p12.toLocaleString());
      setText('advEndpointSignals', endpoint.toLocaleString());
      setText('advNetworkSignals', network.toLocaleString());
      setText('advRareSignals', rare.toLocaleString());
      setText('advConfidenceIndex', `${findings.length ? Math.round((highConfidence / findings.length) * 100) : 0}%`);
      setText('advThreatScore', topScore.toFixed(0));
      setText('advQueueHealth', p12 ? 'Elevated' : findings.length ? 'Monitoring' : 'Clear');
      setText('advPosture', p12 ? 'Active triage' : findings.length ? 'Hunting' : 'Stable');
      setText('advSource', state.sourceFile || 'No source file reported');
      const ring = byId('advThreatRing');
      if (ring) ring.style.setProperty('--risk', `${Math.min(100, topScore)}%`);
      renderTactics(findings);
      renderEntities(findings);
      renderStream(findings);
      renderHeatmap(findings);
      renderParams(findings);
      renderDecisionMatrix(findings);
    }
    function setText(id, value) { const node = byId(id); if (node) node.textContent = value; }
    function renderTactics(findings) {
      const max = Math.max(1, ...tacticMap.map(([, keys]) => keys.reduce((total, key) => total + sum(findings, key), 0)));
      const html = tacticMap.map(([label, keys]) => {
        const count = keys.reduce((total, key) => total + sum(findings, key), 0);
        return `<div><div class="adv-lane"><span><b>${escapeHtml(label)}</b><b>${count.toLocaleString()}</b></span><div style="width:${Math.max(4, (count / max) * 100)}%"></div></div></div>`;
      }).join('');
      byId('advTacticLanes').innerHTML = html || empty('No tactic evidence available');
    }
    function renderEntities(findings) {
      const scores = new Map();
      for (const item of findings) scores.set(entity(item), (scores.get(entity(item)) || 0) + value(item.anomaly_score));
      const rows = [...scores.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([name, score]) => `<div class="adv-row"><span>${escapeHtml(name)}<small>Aggregated entity risk</small></span><strong class="adv-score ${severityClass(score / 2)}">${Math.round(score)}</strong></div>`).join('');
      byId('advEntityRisk').innerHTML = rows || empty('No risky entities in current view');
    }
    function renderStream(findings) {
      const rows = [...findings].sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)).slice(0, 6).map(item => `<div class="adv-row"><span>${escapeHtml(entity(item))}<small>${escapeHtml(item.reason || 'Anomalous behavior')} | ${escapeHtml(item.timestamp || '')}</small></span><strong class="adv-score ${escapeHtml(String(item.severity || 'low').toLowerCase())}">${escapeHtml(item.priority || 'P4')}</strong></div>`).join('');
      byId('advAlertStream').innerHTML = rows || empty('No live findings available');
    }
    function renderHeatmap(findings) {
      const cells = [['Critical', findings.filter(i => i.severity === 'critical').length], ['High', findings.filter(i => i.severity === 'high').length], ['Medium', findings.filter(i => i.severity === 'medium').length], ['Endpoint', sum(findings, 'process_event_count')], ['Network', sum(findings, 'network_event_count') + sum(findings, 'suricata_alert_count')], ['PowerShell', sum(findings, 'powershell_count')], ['LOLBins', sum(findings, 'lolbin_count')], ['Encoded', sum(findings, 'encoded_command_count')], ['Downloads', sum(findings, 'download_command_count')], ['Ports', sum(findings, 'unique_dest_ports')]];
      byId('advHeatmap').innerHTML = cells.map(([label, count]) => `<div class="adv-cell"><strong>${Number(count).toLocaleString()}</strong><span>${escapeHtml(label)}</span></div>`).join('');
    }
    function renderParams(findings) {
      byId('advModelParams').innerHTML = featureKeys.map(key => `<div class="adv-param"><span>${escapeHtml(key.replaceAll('_', ' '))}</span><strong>${sum(findings, key).toLocaleString()}</strong></div>`).join('');
    }
    function renderDecisionMatrix(findings) {
      const actions = [
        ['Containment candidate', findings.filter(i => value(i.anomaly_score) >= 99).length, 'Critical scoring entities for immediate validation'],
        ['Endpoint investigation', sum(findings, 'powershell_count') + sum(findings, 'encoded_command_count'), 'Review Sysmon process creation and script telemetry'],
        ['Network pivot', sum(findings, 'suricata_alert_count') + sum(findings, 'external_connection_count'), 'Pivot on src/dest IP, ports, signatures, and flows'],
        ['Lineage review', sum(findings, 'unexpected_parent_child_count') + sum(findings, 'suspicious_parent_child_count'), 'Validate parent process, user context, and command line']
      ];
      byId('advDecisionMatrix').innerHTML = actions.map(([label, count, text]) => `<div class="adv-signal-card"><strong>${Number(count).toLocaleString()} ${escapeHtml(label)}</strong><span>${escapeHtml(text)}</span></div>`).join('');
    }
    function empty(text) { return `<div class="empty">${escapeHtml(text)}</div>`; }
    function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])); }
    ['minScore', 'severityFilter', 'sortBy', 'searchBox', 'refreshButton'].forEach(id => {
      const node = byId(id);
      if (node) node.addEventListener(id === 'searchBox' ? 'input' : 'change', () => setTimeout(refreshAdvanced, 40));
      if (id === 'refreshButton' && node) node.addEventListener('click', () => setTimeout(refreshAdvanced, 40));
    });
    refreshAdvanced();
    setInterval(refreshAdvanced, 30000);
  })();
</script>
"""


def enhance_dashboard_html(html: str) -> str:
    return (
        html.replace("</head>", f"{ADVANCED_DASHBOARD_STYLE}</head>", 1)
        .replace('<section class="grid">', f"{ADVANCED_DASHBOARD_MARKUP}<section class=\"grid\">", 1)
        .replace("</body>", f"{ADVANCED_DASHBOARD_SCRIPT}</body>", 1)
    )
