/* Global shell, measured situation summary and keyboard command palette. */
(function () {
  let consoleSnapshot = null;
  let consoleSummaryBusy = false;
  let consoleActivityChart = null;
  let consolePaletteVersion = 0;
  let consolePaletteTimer = null;
  let consolePaletteFocus = null;
  const consoleSensorNames = {packet_analyzer:'Packet capture', sysmon_parser:'Sysmon', edr:'Endpoint sensor',
    siem_collector:'SIEM log collection', authlog:'SSH authentication', syslog_receiver:'Syslog receiver',
    snort:'Snort IDS', suricata:'Suricata IDS', zeek:'Zeek NSM'};
  const consolePanelNotes = {
    ml: ['EXPERIMENTAL', 'Isolation Forest is advisory. Training provenance is shown with the model. RF, LSTM and Q-learning remain isolated experiments. Accuracy is unavailable without a valid evaluation.'],
    mitre: ['MIXED', 'Rule presence, purple-team validation, and observed hits are separate signals. Hit counters include mixed sources and current-process history; they do not prove production visibility.'],
    campaigns: ['MIXED', 'Correlation is a hypothesis based on shared source and time, not attacker attribution. Inspect member alerts and provenance before drawing conclusions.'],
    'siem-correlation': ['MIXED', 'Correlation rules generate new detections. Review independent evidence and per-alert provenance before responding.'],
    soar: ['SIMULATED', 'Review the actual response mode and approval gates below. A passed gate is eligibility, not proof of a successful firewall operation. Replay never changes response state.'],
    vulnscan: ['UNAVAILABLE', 'Asset → service → CVE match → validation → patch state. A scanner match is unverified until cross-validation supports it. Unknown patch state is not a confirmed vulnerability.'],
    patch: ['UNAVAILABLE', 'Review detected packages and proposed changes first. Dry-run is the default; inspect the execution mode on each result. Actual application remains gated by server policy.'],
    purple: ['SIMULATED', 'Validation exercises the real detection engine with simulated attacks. Test coverage is not real-world detection accuracy.'],
    health: ['REAL', 'Measured process and module state. LIVE libraries do not imply live sensors. Missing latency, last-event or backlog metrics remain unavailable.'],
    metrics: ['MIXED', 'MTTA/MTTR come from recorded case transitions. The automated false-positive closure ratio is not an analyst FP rate or AI accuracy. Metrics may include demo and legacy cases.'],
    siem: ['MIXED', 'Search the retained SIEM event buffer using text or field=value. Time filters use event timestamps. Durable alert investigations and saved hunts include archived alerts.'],
    hunt: ['MIXED', 'Saved hunts query durable alert history including archives. Delta counts are since the last marked run. Check provenance before promoting an IOC.'],
    labeling: ['MIXED', 'Separate individual analyst labels from weaker group labels. Synthetic and unverified records must not be treated as real-world evaluation evidence.'],
    'alert-history': ['MIXED', 'Durable live and archived evidence. Open any record for its investigation context. Archived records remain read-only.'],
    reputation: ['UNAVAILABLE', 'IP reputation may use demo fallback when the provider is unavailable. A reputation score alone is not evidence of compromise.'],
    report: ['UNAVAILABLE', 'Briefings are advisory summaries. Verify evidence references and the model/data mode before sharing.'],
  };

  function consoleSetText(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }
  function consoleToggleLive() { SOCRealtime.setPaused(!SOCRealtime.paused); }
  function consoleChangeRange(el) {
    SOCUI.hours = Number(el.value);
    consoleLoadSummary(true);
    if (SOCUI.currentPanel === 'alerts') consoleLoadQueue(true);
    if (SOCUI.currentPanel === 'quality') consoleLoadQuality();
    SOCUI.notify('Time range updated for Command Center, the alert queue, entity search and Detection Quality. Specialist panels show their own scope.');
  }

  async function consoleLoadSummary(force) {
    if (consoleSummaryBusy || (!force && SOCRealtime.paused)) return;
    consoleSummaryBusy = true;
    const hours = SOCUI.hours;
    try {
      const data = await SOCUI.request('/api/console/summary?hours=' + hours);
      if (hours !== SOCUI.hours) return;
      consoleSnapshot = data;
      const sensors = data.health.modules.filter(m => consoleSensorNames[m.key]);
      const real = sensors.filter(m => m.mode === 'real').length;
      const unavailable = sensors.filter(m => ['down','off'].includes(m.mode)).length;
      const high = data.queue.counts.filter(c => c.severity === 'HIGH').reduce((n,c) => n + c.count, 0);
      consoleSetText('cc-critical', SOCUI.number(data.incidents.critical));
      const caseSources = data.incidents.provenance || [];
      consoleSetText('cc-case-scope', (caseSources.length === 1 ? caseSources[0] : caseSources.length ? 'MIXED' : 'NO CASE DATA') + ' · current cases / all ages');
      consoleSetText('cc-high', SOCUI.number(high));
      consoleSetText('cc-open', SOCUI.number(data.queue.total));
      consoleSetText('cc-campaigns', SOCUI.number(data.campaigns.count));
      consoleSetText('cc-campaign-scope', data.campaigns.truncated ? 'Sample: latest 5,000 alerts' : 'Observed groups · not attribution');
      consoleSetText('cc-blocks', SOCUI.number(data.response.active_blocks));
      consoleSetText('cc-block-mode', data.response.mode === 'simulate' ? 'SIMULATED · no firewall execution' : data.response.mode.toUpperCase() + ' · recorded active blocks');
      consoleSetText('cc-sensors', real + ' / ' + sensors.length);
      consoleSetText('console-sensor-count', real + '/' + sensors.length);
      consoleSetText('console-situation', data.queue.total ? `${SOCUI.number(data.queue.total)} open alerts need review` : 'No open alerts in the selected range');
      consoleSetText('console-situation-detail', `${real} real sensors · ${unavailable} offline or disabled · review visibility before concluding the environment is quiet.`);
      consoleSetText('console-updated', 'Snapshot ' + data.generated_at + ' · server time');
      const prov = [...new Set(data.activity.counts.map(c => c.provenance))];
      consoleSetText('console-data-label', prov.length === 1 ? prov[0] : prov.length ? 'MIXED SOURCES' : 'NO ALERT DATA');
      const label = document.getElementById('console-data-label');
      if (label) label.className = 'provenance provenance-' + (prov.length === 1 ? prov[0].toLowerCase() : 'mixed');
      consolePaintPriority(data.queue.alerts.slice(0, 6));
      const sensorBox = document.getElementById('console-sensors');
      if (sensorBox) sensorBox.innerHTML = sensors.map(m => {
        const label = {real:'LIVE · REAL',demo:'DEMO',down:'OFFLINE',off:'OFF',live:'SERVICE ONLY'}[m.mode] || 'UNAVAILABLE';
        return `<div class="sensor-row"><span>${consoleSensorNames[m.key]}</span><span class="sensor-state ${m.mode === 'real' ? 'live' : m.mode}"><i class="status-dot"></i>${label}</span></div>`;
      }).join('');
      const response = document.getElementById('console-response');
      const mode = data.response.mode === 'simulate' ? 'SIMULATED' : 'REAL';
      if (response) response.innerHTML = `${SOCUI.provenance({provenance:{state:mode}})}<p><strong>${data.response.approval_required ? 'Manual approval required' : 'Approval policy: automatic'}</strong></p><p>${SOCUI.number(data.response.approvals.length)} pending approvals in recent executions<br/>Confidence threshold ${escapeHtml(String(data.response.min_confidence))}% · block TTL ${escapeHtml(String(data.response.ttl_hours))}h</p><p>Private networks and self-IP protections remain enforced.</p>`;
      const cases = document.getElementById('console-cases');
      if (cases) cases.innerHTML = data.incidents.recent.map(inc => `<button class="console-case" ${act('openIncident',[inc.id])}><strong>#${inc.id} · ${escapeHtml(inc.title)}</strong><small>${sevBadge(inc.severity)} ${SOCUI.provenance(inc)} · ${escapeHtml(inc.status)}</small></button>`).join('') || '<div class="console-empty">No active cases recorded.</div>';
      const pipeline = document.getElementById('console-pipeline');
      if (pipeline) {
        const tel = data.telemetry, points = tel.points || [], probes = tel.probes || [];
        const warnings = points.filter(p => p.slow || p.errors).map(p => p.name + ': p95 ' + p.p95 + 'ms, ' + p.errors + ' recorded errors').concat(probes.filter(p => p.warn || p.error).map(p => p.label + ': ' + (p.error ? 'probe unavailable' : p.value + ' ' + p.unit)));
        const search = points.find(p => p.name === 'console.search');
        const queue = probes.find(p => p.name === 'ai.queue_depth');
        pipeline.innerHTML = `<span class="provenance provenance-real">MEASURED</span><p class="mt-2">${warnings.length ? warnings.map(escapeHtml).join('<br/>') : points.length ? 'No configured telemetry thresholds exceeded.' : 'No timing samples recorded.'}</p><p class="text-muted small">Search p95: ${search ? escapeHtml(String(search.p95)) + 'ms' : 'unavailable'}<br/>AI queue: ${queue?.value != null ? SOCUI.number(queue.value) : 'unavailable'}<br/>Measurement includes demo workload.</p>`;
      }
      consolePaintActivity(data.activity);
      consoleApplyPanelContext(SOCUI.currentPanel);
    } catch (error) {
      consoleSetText('console-situation', 'Operational snapshot unavailable');
      consoleSetText('console-situation-detail', 'Last displayed values may be stale. ' + error.message);
    } finally { consoleSummaryBusy = false; if (hours !== SOCUI.hours) consoleLoadSummary(true); }
  }

  function consolePaintPriority(alerts) {
    const box = document.getElementById('console-priority');
    if (!box) return;
    if (!alerts.length) { box.innerHTML = '<tr><td colspan="6"><div class="console-empty">No open alerts in this range. Check sensor coverage before concluding there is no activity.</div></td></tr>'; return; }
    // Keep the row under the pointer/focus. New snapshots do not sort live rows.
    const current = Array.from(box.querySelectorAll('[data-alert-id]')).map(el => Number(el.dataset.alertId));
    const stable = [...alerts].sort((a,b) => {
      const ai = current.indexOf(a.id), bi = current.indexOf(b.id);
      return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi);
    });
    reconcileList(box, stable, a => a.id, a => `<tr data-alert-id="${a.id}" tabindex="0" role="button" aria-label="Investigate alert ${a.id}" ${act('consoleOpenInvestigation',[a.id])}><td>${sevBadge(a.severity)}</td><td><span class="detection-title">${escapeHtml(a.description || a.threat_type)}</span><span class="detection-meta">#${a.id} · ${SOCUI.entity(a.src_ip)} ${a.dst_ip ? ' → ' + SOCUI.entity(a.dst_ip) : ''}</span></td><td>${SOCUI.confidence(a)}</td><td>${SOCUI.provenance(a)}</td><td class="text-nowrap">${escapeHtml((a.timestamp || '').slice(11))}</td><td><i class="fa fa-angle-right text-muted"></i></td></tr>`);
  }

  function consolePaintActivity(activity) {
    const canvas = document.getElementById('console-activity-chart');
    if (!canvas) return;
    const hours = [...new Set(activity.timeline.map(row => row.hour))];
    const severities = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    const colors = ['--severity-critical','--severity-high','--severity-medium','--severity-low','--severity-info'];
    const datasets = severities.map((sev, i) => ({label:sev, data:hours.map(hour => activity.timeline.filter(r => r.hour === hour && r.severity === sev).reduce((sum,r) => sum+r.count,0)), backgroundColor:cssVar(colors[i]), borderRadius:2, maxBarThickness:24}));
    if (!consoleActivityChart) consoleActivityChart = new Chart(canvas.getContext('2d'), {type:'bar',data:{labels:[],datasets:[]},options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{position:'bottom',labels:{boxWidth:7,boxHeight:7,color:cssVar('--text-tertiary'),font:{size:11}}}},scales:{x:{stacked:true,grid:{display:false},ticks:{color:cssVar('--text-tertiary'),maxTicksLimit:12}},y:{stacked:true,beginAtZero:true,grid:{color:cssVar('--border-subtle')},ticks:{color:cssVar('--text-tertiary'),precision:0}}}}});
    consoleActivityChart.data = {labels:hours.map(hour => hour.slice(5) + ':00'), datasets};
    consoleActivityChart.update('none');
    const counts = activity.counts.reduce((out,c) => { out[c.provenance] = (out[c.provenance] || 0) + c.count; return out; },{});
    const description = `${SOCUI.number(activity.total)} stored alerts · ` + (Object.entries(counts).map(([p,n]) => `${p} ${SOCUI.number(n)}`).join(' · ') || 'No recorded events in this range.');
    consoleSetText('console-activity-description', description);
    canvas.setAttribute('aria-label', description);
  }

  function consoleApplyPanelContext(panel) {
    const box = document.getElementById('console-workspace-context');
    if (!box) return;
    const note = consolePanelNotes[panel];
    if (note) {
      let state = note[0];
      if (panel === 'soar') state = consoleSnapshot?.response.mode === 'simulate' ? 'SIMULATED' : consoleSnapshot ? 'REAL' : 'UNAVAILABLE';
      box.innerHTML = SOCUI.provenance({provenance:{state}}) + escapeHtml(note[1]); box.hidden = false;
    } else { box.hidden = true; }
    document.querySelectorAll('.sidebar-link').forEach(a => { if (a.dataset.panel === panel) a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current'); });
    if (panel === 'quality') consoleLoadQuality();
    const root = document.getElementById('panel-' + panel);
    root?.querySelectorAll('.panel-note').forEach(note => {
      if (!note.querySelector('.fa-lightbulb') || note.tagName === 'DETAILS') return;
      const details = document.createElement('details'); details.className = note.className;
      const header = note.querySelector('.card-panel-header');
      const summary = document.createElement('summary'); summary.textContent = header?.textContent.trim() || 'Workspace guide';
      header?.remove(); details.appendChild(summary);
      while (note.firstChild) details.appendChild(note.firstChild);
      note.replaceWith(details);
    });
  }

  function consoleOpenPalette(query) {
    const dialog = document.getElementById('command-palette');
    if (!dialog) return;
    consolePaletteFocus = document.activeElement;
    if (!dialog.open) dialog.showModal();
    const input = document.getElementById('palette-input');
    input.value = typeof query === 'string' ? query : '';
    input.focus();
    consolePaletteResults(input.value);
  }
  function consoleClosePalette() {
    consolePaletteVersion++;
    document.getElementById('command-palette')?.close();
    consolePaletteFocus?.focus();
  }
  function consoleSearchEntity(value) { consoleOpenPalette(value); }
  function consoleNotifications() {
    SOCUI.notify('Notifications use the recorded analyst queue and response approvals. There is no separate notification inbox.');
    SOCUI.navigate('alerts');
  }
  function consolePaletteNavigate(panel) { consoleClosePalette(); SOCUI.navigate(panel); }
  function consolePaletteAlert(id) { consoleClosePalette(); consoleOpenInvestigation(id); }
  function consolePaletteIncident(id) { consoleClosePalette(); openIncident(id); }
  function consolePaletteRealtime(paused) { consoleClosePalette(); SOCRealtime.setPaused(paused); }

  async function consolePaletteResults(query) {
    const version = ++consolePaletteVersion;
    const box = document.getElementById('palette-results');
    const q = query.toLowerCase().trim();
    const nav = Array.from(document.querySelectorAll('.sidebar-link')).filter(el => !q || el.textContent.toLowerCase().includes(q));
    let html = '<div class="palette-group-label">Navigate</div>' + nav.slice(0, q ? 12 : 6).map(el => `<button class="palette-result" ${act('consolePaletteNavigate',[el.dataset.panel])}><i class="fa fa-arrow-turn-down fa-rotate-270"></i><span>${escapeHtml(el.querySelector('span')?.textContent || el.textContent)}</span></button>`).join('');
    const commands = [['Pause realtime',true],['Resume realtime',false]].filter(([label]) => !q || label.toLowerCase().includes(q));
    html += commands.map(([label, paused]) => `<button class="palette-result" ${act('consolePaletteRealtime',[paused])}><i class="fa fa-pause"></i>${label}</button>`).join('');
    if (!q || 'view critical only'.includes(q)) html += `<button class="palette-result" ${act('consolePaletteCritical')}>View CRITICAL only</button>`;
    box.innerHTML = html;
    if (q.length < 2) { consoleSelectPalette(0); return; }
    box.insertAdjacentHTML('beforeend', '<div id="palette-loading" class="console-empty">Searching stored evidence…</div>');
    try {
      const data = await SOCUI.request('/api/console/entities?' + new URLSearchParams({q:query,hours:SOCUI.hours}));
      if (version !== consolePaletteVersion) return;
      for (const group of data.groups) {
        if (!group.items.length) continue;
        html += `<div class="palette-group-label">${escapeHtml(group.type)} ${group.type === 'Alerts' ? '· ' + SOCUI.number(data.total_alerts) + ' matches' : ''}</div>`;
        html += group.items.map(item => group.type === 'Alerts'
          ? `<button class="palette-result" ${act('consolePaletteAlert',[item.id])}>${sevBadge(item.severity)}<span>#${item.id} · ${escapeHtml(item.threat_type)}<small>${escapeHtml(item.src_ip || '')} · ${escapeHtml(item.timestamp)}</small></span>${SOCUI.provenance(item)}</button>`
          : group.type === 'Incidents'
            ? `<button class="palette-result" ${act('consolePaletteIncident',[item.id])}><i class="fa fa-folder-open"></i><span>#${item.id} ${escapeHtml(item.title)}<small>${escapeHtml(item.status)}</small></span></button>`
            : `<button class="palette-result" ${act('consolePaletteNavigate',['watchlist'])}><i class="fa fa-fingerprint"></i><span>${escapeHtml(item.value)}<small>${escapeHtml(item.type)} · ${escapeHtml(item.note || '')}</small></span></button>`).join('');
      }
      if (!data.groups.some(g => g.items.length)) html += '<div class="console-empty">No matching evidence in this range.<br/>Try a longer time range or open the alert archive.</div>';
      box.innerHTML = html;
      consoleSelectPalette(0);
    } catch (error) { if (version === consolePaletteVersion) box.innerHTML = html + `<div class="console-empty">${escapeHtml(error.message)}</div>`; }
  }
  function consolePaletteCritical() { consoleClosePalette(); consoleQueueView('critical'); }
  function consoleSelectPalette(index) {
    const results = Array.from(document.querySelectorAll('.palette-result'));
    if (!results.length) return;
    const selected = results[(index + results.length) % results.length];
    results.forEach(el => el.classList.toggle('selected', el === selected));
    selected.scrollIntoView({block:'nearest'});
  }

  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); consoleOpenPalette(); }
    const dialog = document.getElementById('command-palette');
    if (!dialog?.open || !['ArrowDown','ArrowUp','Enter'].includes(event.key)) return;
    const rows = Array.from(dialog.querySelectorAll('.palette-result'));
    const index = rows.findIndex(el => el.classList.contains('selected'));
    if (event.key === 'Enter') { if (event.target.id === 'palette-input') { event.preventDefault(); rows[index]?.click(); } }
    else { event.preventDefault(); consoleSelectPalette(index + (event.key === 'ArrowDown' ? 1 : -1)); }
  });
  document.addEventListener('soc:panel', event => consoleApplyPanelContext(event.detail));
  document.addEventListener('soc:resume', () => consoleLoadSummary(true));
  document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('palette-input');
    input?.addEventListener('input', () => { clearTimeout(consolePaletteTimer); consolePaletteVersion++; consolePaletteTimer = setTimeout(() => consolePaletteResults(input.value),250); });
    SOCRealtime.subscribe(state => {
      const button = document.getElementById('console-live');
      button?.setAttribute('aria-pressed', String(state.paused));
      consoleSetText('badge-status', state.paused ? 'PAUSED' : socket.connected ? 'LIVE' : 'RECONNECTING');
      consoleSetText('console-pending', state.paused ? `+${SOCUI.number(state.pending)} new events${state.omitted ? ' · local buffer capped' : ''} · Resume` : 'Pause display updates');
    });
    socket.on('connect', () => { SOCRealtime.changed(); consoleLoadSummary(true); });
    socket.on('disconnect', () => { consoleSetText('badge-status','DISCONNECTED'); consoleSetText('console-updated','Connection lost · displayed snapshot may be stale'); });
    const stream = document.getElementById('live-stream')?.closest('.card-panel');
    if (stream) document.getElementById('console-stream-slot').appendChild(stream);
    const disclosure = document.querySelector('.console-legacy');
    disclosure?.addEventListener('toggle', () => { if (disclosure.open) initMap(); });
    SOCUI.request('/api/whoami').then(data => {
      consoleSetText('console-environment',data.demo ? 'DEMO ENV' : 'REAL ENV');
      consoleSetText('console-user-name',data.user || (data.auth_enabled ? 'Analyst' : 'Local workspace · authentication off'));
      consoleSetText('console-avatar',(data.user || 'A')[0].toUpperCase());
    }).catch(() => {});
    consoleLoadSummary(true);
    setInterval(() => { if (!document.hidden && !SOCRealtime.paused) consoleLoadSummary(); },15000);
  });
  Object.assign(window, {consoleApplyPanelContext, consoleChangeRange, consoleClosePalette,
    consoleLoadSummary, consoleNotifications, consoleOpenPalette, consolePaletteAlert,
    consolePaletteCritical, consolePaletteIncident, consolePaletteNavigate, consolePaletteRealtime,
    consoleSearchEntity, consoleToggleLive});
})();
