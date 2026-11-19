const $ = (id) => document.getElementById(id);
let appState = { status: null, devices: [], events: [], scans: [] };

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}
function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function toast(message, type = 'success') {
  const el = document.createElement('div'); el.className = `toast ${type === 'error' ? 'error' : ''}`; el.textContent = message;
  $('toast-region').appendChild(el); setTimeout(() => el.remove(), 4200);
}
function fmtDate(value) {
  if (!value) return '—';
  const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function shortDate(value) {
  if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
}
function statusBadge(status) {
  const map = { known: ['Approved','status-known'], review: ['Needs review','status-review'], ignored: ['Ignored','status-ignored'] };
  const [label, cls] = map[status] || ['Unknown','status-neutral']; return `<span class="status-pill ${cls}">${label}</span>`;
}
function deviceIcon(name = '') {
  const text = `${name}`.toLowerCase();
  if (text.includes('phone') || text.includes('android') || text.includes('iphone')) return '▯';
  if (text.includes('printer')) return '▤';
  if (text.includes('router') || text.includes('gateway')) return '⌘';
  if (text.includes('tv')) return '▣';
  return '▱';
}
function showPage(page) {
  document.querySelectorAll('.page').forEach(el => el.classList.toggle('active', el.id === `page-${page}`));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.page === page));
  const active = document.querySelector(`.nav-item[data-page="${page}"]`);
  $('crumb-current').textContent = active ? active.textContent.trim().replace(/\s+\d+$/, '') : 'Overview';
  $('sidebar').classList.remove('open');
  if (page === 'devices') renderDevices();
  if (page === 'events') renderEvents();
  if (page === 'audit') renderAudit();
  if (page === 'investigation') { renderReviewQueue(); refreshAIStatus(); }
  if (page === 'reports') renderScans();
}

async function refreshAll() {
  try {
    const [status, devices, events, scans] = await Promise.all([
      api('/api/status'), api('/api/devices'), api('/api/events'), api('/api/scans')
    ]);
    appState = { status, devices, events, scans };
    renderOverview(); renderDevices(); renderEvents(); renderReviewQueue(); renderScans();
  } catch (error) { toast(error.message, 'error'); }
}
function renderOverview() {
  const s = appState.status || {};
  $('metric-devices').textContent = s.device_count ?? '—';
  $('metric-review').textContent = s.review_count ?? '—';
  $('metric-alerts').textContent = s.alert_count ?? '—';
  $('nav-device-count').textContent = s.device_count ?? '0';
  $('nav-alert-count').textContent = s.alert_count ?? '0';
  $('network-context').textContent = s.network ? `${s.interface || 'Network interface'} · ${s.ip || 'IP unavailable'} · ${s.network}${s.gateway ? ` · Gateway ${s.gateway}` : ''}` : 'No active local IPv4 network detected. Connect to Wi-Fi and refresh.';
  $('gateway-address').textContent = s.gateway || 'Not detected';
  if (s.last_scan) {
    $('metric-last-scan').textContent = shortDate(s.last_scan.created_at);
    $('metric-scan-method').textContent = `${s.last_scan.devices_found} devices · ${s.last_scan.method}`;
  } else { $('metric-last-scan').textContent = 'Not yet'; $('metric-scan-method').textContent = 'Run a scan to populate inventory'; }
  const recent = appState.devices.slice(0, 5);
  $('overview-devices').innerHTML = recent.length ? recent.map(d => `<tr><td><div class="device-cell"><span class="device-symbol">${deviceIcon(d.hostname)}</span><div><div class="device-name">${escapeHtml(d.hostname || 'Unnamed device')}</div><div class="device-sub">${escapeHtml(d.vendor || 'Manufacturer unavailable')}</div></div></div></td><td class="mono">${escapeHtml(d.ip)}</td><td class="mono">${escapeHtml(d.mac)}</td><td>${statusBadge(d.status)}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No devices recorded yet. Run a local network scan to begin.</td></tr>';
  $('overview-events').innerHTML = appState.events.slice(0, 4).map(eventHtml).join('') || '<div class="empty-state compact">No security events have been recorded.</div>';
}
function eventHtml(e) {
  return `<div class="event-row"><span class="event-indicator ${escapeHtml(e.severity)}"></span><div class="event-content"><div class="event-title">${escapeHtml(e.title)}</div><div class="event-detail">${escapeHtml(e.detail)}</div></div><time class="event-time">${escapeHtml(shortDate(e.created_at))}</time></div>`;
}
function renderDevices(filter = $('device-search')?.value || '') {
  const q = filter.toLowerCase();
  const rows = appState.devices.filter(d => [d.hostname,d.ip,d.mac,d.vendor,d.status].join(' ').toLowerCase().includes(q));
  $('device-total').textContent = `${rows.length} device${rows.length === 1 ? '' : 's'}`;
  $('device-rows').innerHTML = rows.length ? rows.map(d => `<tr><td><div class="device-cell"><span class="device-symbol">${deviceIcon(d.hostname)}</span><div><div class="device-name">${escapeHtml(d.hostname || 'Unnamed device')}</div><div class="device-sub">${escapeHtml(d.notes || 'No notes')}</div></div></div></td><td class="mono">${escapeHtml(d.ip)}</td><td class="mono">${escapeHtml(d.mac)}</td><td>${escapeHtml(d.vendor || '—')}</td><td>${escapeHtml(shortDate(d.last_seen))}</td><td>${statusBadge(d.status)}</td><td><div class="row-actions">${d.status !== 'known' ? `<button class="mini-action approve" data-device-action="known" data-mac="${escapeHtml(d.mac)}">Approve</button>` : ''}<button class="mini-action" data-device-action="review" data-mac="${escapeHtml(d.mac)}">Review</button><button class="mini-action" data-device-action="ignored" data-mac="${escapeHtml(d.mac)}">Ignore</button></div></td></tr>`).join('') : '<tr><td colspan="7" class="empty-cell">No matching devices. Run a scan or adjust your search.</td></tr>';
}
function renderEvents() {
  $('all-events').innerHTML = appState.events.length ? appState.events.map(eventHtml).join('') : '<div class="empty-state">No events to display. Events are created when a scan discovers a new device or inventory changes.</div>';
}
function renderReviewQueue() {
  const review = appState.devices.filter(d => d.status === 'review');
  $('review-queue').innerHTML = review.length ? review.map(d => `<div class="review-item"><strong>${escapeHtml(d.hostname || 'Unnamed device')}</strong><p>${escapeHtml(d.ip)} · ${escapeHtml(d.mac)}</p><div class="review-actions"><button class="mini-action approve" data-device-action="known" data-mac="${escapeHtml(d.mac)}">Approve device</button><button class="mini-action" data-device-action="ignored" data-mac="${escapeHtml(d.mac)}">Ignore</button></div></div>`).join('') : '<div class="empty-state compact">No devices currently need review.</div>';
}
function renderAudit() {
  const checks = [
    ['Wi-Fi encryption','Use WPA3-Personal where supported, or WPA2-AES. Avoid WEP and legacy WPA.','01'],
    ['Wi-Fi Protected Setup (WPS)','Disable WPS if it is not required. PIN-based WPS can weaken network security.','02'],
    ['Administrator credentials','Replace default router administrator credentials with a unique, strong password.','03'],
    ['Router firmware','Install security updates from the router manufacturer while the device remains supported.','04'],
    ['Guest network separation','Use a separate guest network for visitors and untrusted smart-home devices when available.','05'],
    ['Remote administration','Disable internet-facing remote administration unless there is a specific secured requirement.','06']
  ];
  $('audit-checks').innerHTML = checks.map(c => `<article class="audit-check"><span class="audit-check-icon">${c[2]}</span><div><h3>${c[0]}</h3><p>${c[1]}</p><span class="manual-tag">VERIFY IN ROUTER SETTINGS</span></div></article>`).join('');
}

async function refreshAIStatus() {
  try {
    const status = await api('/api/ai/status');
    const pill = $('ai-status-pill');
    $('ai-model-label').textContent = `${status.provider} · ${status.model}`;
    if (!status.available) {
      pill.textContent = 'Ollama offline'; pill.className = 'status-pill status-review';
      $('ai-status-detail').textContent = 'Install Ollama and start it to enable private, local AI analysis.';
      $('run-ai-button').disabled = true;
    } else if (!status.model_installed) {
      pill.textContent = 'Model not installed'; pill.className = 'status-pill status-review';
      $('ai-status-detail').textContent = `Ollama is running. Run “ollama pull ${status.model}” in a terminal.`;
      $('run-ai-button').disabled = true;
    } else {
      pill.textContent = 'Local AI ready'; pill.className = 'status-pill status-known';
      $('ai-status-detail').textContent = 'Analysis runs locally on this computer. No paid API key or cloud upload is required.';
      $('run-ai-button').disabled = false;
    }
  } catch (error) {
    $('ai-status-pill').textContent = 'AI unavailable';
    $('ai-status-pill').className = 'status-pill status-review';
    $('ai-status-detail').textContent = error.message;
    $('run-ai-button').disabled = true;
  }
}
function renderAIReport(report) {
  const agents = (report.agents || []).map(item => `<article class="ai-agent-result"><div class="ai-agent-title">${escapeHtml(item.agent)}</div><div class="ai-agent-copy">${escapeHtml(item.analysis).replace(/\n/g, '<br>')}</div></article>`).join('');
  $('ai-results').innerHTML = `<section class="ai-summary"><div class="ai-summary-heading"><strong>Lead analyst assessment</strong><span>${escapeHtml(report.model)} · ${escapeHtml(shortDate(report.created_at))}</span></div><div class="ai-summary-copy">${escapeHtml(report.summary).replace(/\n/g, '<br>')}</div></section><div class="ai-agent-grid">${agents}</div><div class="ai-evidence-note">Evidence supplied: ${report.evidence_scope.devices_included} devices · ${report.evidence_scope.events_included} recent events. The model did not inspect raw packets or router configuration.</div>`;
}
async function runAIInvestigation() {
  const button = $('run-ai-button');
  button.disabled = true; button.textContent = 'Investigating…';
  $('ai-results').innerHTML = '<div class="ai-progress">Running four specialist analyses and preparing the consolidated assessment. This may take a few minutes on a local computer.</div>';
  try {
    const report = await api('/api/ai/investigate', { method: 'POST' });
    renderAIReport(report);
    toast('Local AI investigation completed.');
  } catch (error) {
    $('ai-results').innerHTML = `<div class="notice notice-warning"><div><strong>AI investigation could not run</strong><p>${escapeHtml(error.message)}</p></div></div>`;
    toast(error.message, 'error');
  } finally {
    button.textContent = 'Run AI investigation';
    await refreshAIStatus();
  }
}

function renderScans() {
  $('scan-history').innerHTML = appState.scans.length ? appState.scans.map(s => `<tr><td>${escapeHtml(fmtDate(s.created_at))}</td><td class="mono">${escapeHtml(s.network || '—')}</td><td>${s.devices_found}</td><td>${escapeHtml(s.method)}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No scans recorded yet.</td></tr>';
}

function openScanModal() {
  const s = appState.status || {};
  $('modal-network').textContent = s.network ? `${s.network} · Interface ${s.interface || 'unknown'}` : 'No local network detected';
  $('scan-confirm').checked = false; $('confirm-scan').disabled = !s.network;
  $('scan-modal').hidden = false;
}
function closeScanModal() { $('scan-modal').hidden = true; }
async function runScan() {
  closeScanModal();
  const buttons = [$('scan-button'), $('scan-button-devices')].filter(Boolean);
  buttons.forEach(b => { b.disabled = true; b.dataset.original = b.innerHTML; b.textContent = 'Scanning…'; });
  try {
    const result = await api('/api/scan', { method: 'POST', body: JSON.stringify({ confirm_authorized: true }) });
    await refreshAll();
    toast(`Scan complete: ${result.found} devices found, ${result.new_devices} new.`);
    if (result.note) toast(result.note, 'error');
  } catch (error) { toast(error.message, 'error'); }
  finally { buttons.forEach(b => { b.disabled = false; b.innerHTML = b.dataset.original || '⌕ Scan local network'; }); }
}
async function updateDevice(mac, status) {
  try { await api(`/api/devices/${encodeURIComponent(mac)}`, { method: 'PATCH', body: JSON.stringify({ status }) }); await refreshAll(); toast(`Device marked as ${status}.`); }
  catch (error) { toast(error.message, 'error'); }
}
async function exportReport() {
  try {
    const data = await api('/api/export');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `network-guard-report-${new Date().toISOString().slice(0,10)}.json`; a.click(); URL.revokeObjectURL(url);
    toast('Report exported.');
  } catch (error) { toast(error.message, 'error'); }
}

document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => showPage(button.dataset.page)));
document.querySelectorAll('[data-goto]').forEach(button => button.addEventListener('click', () => showPage(button.dataset.goto)));
$('device-search').addEventListener('input', e => renderDevices(e.target.value));
$('scan-button').addEventListener('click', openScanModal); $('scan-button-devices').addEventListener('click', openScanModal);
$('cancel-scan').addEventListener('click', closeScanModal); $('confirm-scan').addEventListener('click', runScan);
$('scan-confirm').addEventListener('change', e => $('confirm-scan').disabled = !e.target.checked || !appState.status?.network);
$('refresh-button').addEventListener('click', refreshAll); $('refresh-events').addEventListener('click', refreshAll);
$('export-button').addEventListener('click', exportReport); $('export-button-secondary').addEventListener('click', exportReport);
$('mobile-menu').addEventListener('click', () => $('sidebar').classList.toggle('open'));
$('run-ai-button').addEventListener('click', runAIInvestigation);
document.addEventListener('click', e => { const button = e.target.closest('[data-device-action]'); if (button) updateDevice(button.dataset.mac, button.dataset.deviceAction); });

renderAudit();
refreshAll();
refreshAIStatus();
