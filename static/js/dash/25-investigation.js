/* Evidence workspace. Native dialogs, explicit provenance, no response tools in AI. */
(function () {
  let investigationContext = null;
  let investigationVersion = 0;
  let investigationTab = 'evidence';
  let investigationReturnFocus = null;
  let investigationAction = null;
  let investigationBrief = null;
  let investigationCopilotRequest = 0;

  function consoleCloseInvestigation() {
    investigationVersion++;
    document.getElementById('investigation-drawer')?.close();
    investigationReturnFocus?.focus();
  }
  async function consoleOpenInvestigation(id) {
    const version = ++investigationVersion;
    const drawer = document.getElementById('investigation-drawer');
    if (!drawer) return;
    if (!drawer.open) investigationReturnFocus = document.activeElement;
    investigationContext = null;
    investigationBrief = null;
    investigationTab = 'evidence';
    document.getElementById('investigation-title').textContent = 'Loading stored evidence…';
    document.getElementById('investigation-reference').textContent = 'ALERT #' + id;
    document.getElementById('investigation-meta').textContent = '';
    document.getElementById('investigation-content').innerHTML = '<div class="console-empty">Retrieving alert, evidence, decisions and audit history…</div>';
    document.getElementById('investigation-actions').textContent = '';
    drawer.querySelectorAll('.investigation-tabs button').forEach((b,i) => b.classList.toggle('active', i === 0));
    if (!drawer.open) drawer.showModal();
    try {
      const context = await SOCUI.request('/api/console/alerts/' + Number(id));
      if (version !== investigationVersion) return;
      investigationContext = context;
      investigationBrief = context.brief;
      const alert = context.alert;
      document.getElementById('investigation-title').textContent = alert.threat_type.replaceAll('_',' ');
      document.getElementById('investigation-reference').textContent = `ALERT #${alert.id} / ${context.storage}`;
      document.getElementById('investigation-meta').innerHTML = `${sevBadge(alert.severity)} ${SOCUI.provenance(alert)} <span>${escapeHtml(alert.status)}</span><span>Confidence ${SOCUI.confidence(alert)}</span><span>${escapeHtml(alert.timestamp)} · server time</span>`;
      document.getElementById('investigation-actions').innerHTML = alert.archived
        ? '<span class="text-muted">Archived evidence is read-only. Use saved hunts or add an individual analyst label in the labeling workspace.</span>'
        : `<button class="btn btn-sm btn-cyan" ${act('consoleAnalystAction',['ACK'])}>Acknowledge</button><button class="btn btn-sm btn-outline-secondary" ${act('consoleAnalystAction',['TRUE_POSITIVE'])}>True positive</button><button class="btn btn-sm btn-outline-secondary" ${act('consoleAnalystAction',['FALSE_POSITIVE'])}>False positive</button><button class="btn btn-sm btn-outline-secondary" ${act('consoleAnalystAction',['CLOSED'])}>Close with reason</button><button class="btn btn-sm btn-outline-secondary ms-auto" ${act('consoleExportEvidence')}>Export evidence</button>`;
      consoleRenderInvestigation();
      if (drawer.open && !drawer.contains(document.activeElement)) drawer.querySelector('button')?.focus();
    } catch (error) {
      if (version === investigationVersion) document.getElementById('investigation-content').innerHTML = `<div class="console-empty">${escapeHtml(error.message)}</div>`;
    }
  }
  function consoleInvestigationTab(tab, button) {
    investigationTab = tab;
    document.querySelectorAll('.investigation-tabs button').forEach(b => b.classList.toggle('active', b === button));
    consoleRenderInvestigation();
    document.getElementById('investigation-content').scrollTop = 0;
  }
  function investigationRaw(value) { return `<pre class="raw-evidence">${escapeHtml(JSON.stringify(value, null, 2))}</pre>`; }
  function consoleRenderInvestigation() {
    const box = document.getElementById('investigation-content');
    const context = investigationContext;
    if (!context || !box) return;
    const alert = context.alert, details = context.evidence;
    if (investigationTab === 'evidence') {
      const fields = [['Source entity',alert.src_ip],['Destination',alert.dst_ip],['Asset / host',details.hostname || details.host || details.computer],['Process',details.process || details.image || details.cmdline],['User',details.user || details.username],['Detection rule',details.rule_id || details.sid || details.rule || details.signature_id],['Source',details.source || details.siem_source || details.sensor],['Assignee',alert.assignee],['Analyst verdict',alert.verdict],['Verdict rationale',alert.verdict_reason]];
      box.innerHTML = `<section class="investigation-section"><h3>Detection evidence</h3><p>${escapeHtml(alert.description || 'No description recorded.')}</p><dl class="evidence-fields">${fields.map(([key,value]) => `<div class="evidence-field"><dt>${key}</dt><dd>${['Source entity','Destination','Asset / host','User','Detection rule'].includes(key) && value ? SOCUI.entity(value) : escapeHtml(String(value || 'Not recorded'))}</dd></div>`).join('')}</dl></section><section class="investigation-section"><h3>Source provenance</h3><p>${SOCUI.provenance(alert)} ${escapeHtml(alert.provenance.reason)}</p></section><section class="investigation-section"><h3>ATT&CK mapping</h3>${context.techniques.map(t => `<button class="btn btn-sm btn-outline-secondary me-2 mb-2" ${act('consolePivotTechnique',[String(t.technique)])}>${escapeHtml(String(t.technique))} · ${escapeHtml(t.basis)}</button>`).join('') || '<p>No technique mapping recorded.</p>'}</section><section class="investigation-section"><h3>Raw & normalized evidence</h3>${investigationRaw(details)}</section><section class="investigation-section"><h3>Related alerts</h3><p>Latest matches within 7 days, same provenance. Shared entities are investigation leads, not proof of one attack.</p>${context.related_alerts.map(a => `<button class="console-case" ${act('consoleOpenInvestigation',[a.id])}><strong>#${a.id} ${escapeHtml(a.threat_type)}</strong><small>${sevBadge(a.severity)} ${SOCUI.provenance(a)} ${escapeHtml(a.timestamp)}</small></button>`).join('') || '<p>No related alerts in the retained query results.</p>'}</section><section class="investigation-section"><h3>Linked incidents</h3>${context.incidents.map(i => `<button class="console-case" ${act('consolePivotIncident',[i.id])}>#${i.id} ${escapeHtml(i.title)} · ${escapeHtml(i.status)}</button>`).join('') || '<p>No exact alert-to-incident link recorded.</p>'}</section>`;
    } else if (investigationTab === 'timeline') {
      box.innerHTML = `<section class="investigation-section"><h3>Recorded sequence</h3><p>Only timestamped evidence is placed on this timeline. Missing enrichment, correlation, or closure timestamps are not inferred.</p><ol class="evidence-timeline">${context.timeline.map(e => `<li><strong>${escapeHtml(e.stage)}</strong><time>${escapeHtml(e.timestamp || 'Timestamp unavailable')}</time><p>${escapeHtml(e.text || '')}</p><small class="text-muted">${escapeHtml(e.reference)}</small></li>`).join('')}</ol></section>`;
    } else if (investigationTab === 'copilot') {
      box.innerHTML = `<section class="investigation-section"><h3>Analyst copilot · alert #${alert.id}</h3><p>Facts are drawn from stored evidence. Model output is advisory. No conversational action can block, patch, or terminate a process.</p><div class="copilot-intents">${['Summarize evidence','Suggest investigation steps','Explain response decision','Generate handoff summary'].map(intent => `<button class="btn btn-sm btn-outline-secondary" ${act('consoleAskCopilot',[intent])}>${intent}</button>`).join('')}</div><div id="investigation-brief">${consoleBriefHtml(investigationBrief)}</div></section><section class="investigation-section"><h3>Retained triage outputs</h3><p>These are model conclusions, not analyst verdicts or raw evidence.</p>${context.ai.map(item => `<details class="mb-3"><summary>${escapeHtml(item.timestamp)} · ${escapeHtml(item.model)} ${item.model === 'demo' ? SOCUI.provenance({origin:'demo'}) : ''}</summary>${investigationRaw(item.result)}</details>`).join('') || '<p>No retained triage output available.</p>'}</section>`;
    } else {
      box.innerHTML = `<section class="investigation-section"><h3>Why did the system respond?</h3><p>Recorded gate outcomes and immutable decision inputs. A gate pass alone does not establish response success.</p>${context.decisions.map(record => `<div class="console-card mb-3"><div class="console-card-heading"><h2>Decision #${record.id}</h2>${SOCUI.provenance({provenance:{state:record.thresholds?.block_mode === 'simulate' ? 'SIMULATED' : record.thresholds?.block_mode ? 'REAL' : 'UNAVAILABLE'}})}<span class="ms-auto">${escapeHtml(record.outcome_label || record.outcome || 'Outcome unavailable')}</span></div><div class="console-card-body"><p>${escapeHtml(record.ts)} · ${escapeHtml(record.reason || '')}</p><div class="response-gates">${record.gates.map(g => `<div class="response-gate ${g.passed ? 'passed' : ''}"><span>${g.passed ? 'PASS' : 'HOLD'}</span><div>${escapeHtml(g.label || g.id)}<small>Observed: ${escapeHtml(JSON.stringify(g.actual))} · Required: ${escapeHtml(JSON.stringify(g.required))}</small></div></div>`).join('')}</div><details class="mt-3"><summary>Immutable decision inputs</summary>${investigationRaw(record.signals)}</details><button class="btn btn-sm btn-outline-secondary mt-3" ${act('consolePivotReplay',[record.id])}>Open simulated replay</button></div></div>`).join('') || '<p>No SOAR decision is linked to this alert ID.</p>'}</section><section class="investigation-section"><h3>Analyst audit trail</h3>${context.audit.map(e => `<div class="console-case"><strong>${escapeHtml(e.action)} · ${escapeHtml(e.actor)}</strong><small>${escapeHtml(e.ts)}</small><p>${escapeHtml(e.detail)}</p></div>`).join('') || '<p>No analyst audit entries linked to this alert.</p>'}</section>`;
    }
  }
  function consoleBriefHtml(brief) {
    if (!brief) return '<div class="console-empty">No briefing available.</div>';
    return `<div class="workspace-context">${brief.generated ? 'AI ADVISORY · verify model inferences' : 'EVIDENCE SUMMARY · deterministic, not generated analysis'}</div>` + [['facts','FACTS'],['inferences','INFERENCES'],['recommendations','RECOMMENDATIONS'],['unknowns','UNKNOWN / MISSING DATA']].map(([key,label]) => `<section class="brief-section"><h3>${label}</h3><ul>${(brief[key]?.length ? brief[key] : ['None recorded.']).map(line => `<li>${escapeHtml(line)}</li>`).join('')}</ul></section>`).join('');
  }
  async function consoleAskCopilot(intent) {
    if (!investigationContext) return;
    const sequence = ++investigationCopilotRequest;
    const id = investigationContext.alert.id, version = investigationVersion;
    document.querySelectorAll('.copilot-intents button').forEach(button => { button.disabled = true; });
    const box = document.getElementById('investigation-brief');
    if (box) box.innerHTML = '<div class="console-empty">Preparing a context-bound briefing…</div>';
    try {
      const result = await SOCUI.request('/api/console/copilot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_id:id,intent})});
      if (version !== investigationVersion || sequence !== investigationCopilotRequest) return;
      investigationBrief = result;
      const target = document.getElementById('investigation-brief');
      if (target) target.innerHTML = consoleBriefHtml(result);
    } catch (error) { if (version === investigationVersion && sequence === investigationCopilotRequest && box?.isConnected) box.textContent = error.message; }
    finally { if (version === investigationVersion && sequence === investigationCopilotRequest) document.querySelectorAll('.copilot-intents button').forEach(button => { button.disabled = false; }); }
  }
  function consolePivotIncident(id) { consoleCloseInvestigation(); openIncident(id); }
  function consolePivotTechnique(technique) { consoleCloseInvestigation(); SOCUI.navigate('mitre'); setTimeout(() => { if (typeof showTechniqueDetail === 'function') showTechniqueDetail(technique); else consoleSearchEntity(technique); },250); }
  function consolePivotReplay(id) { consoleCloseInvestigation(); SOCUI.navigate('soar'); showBlockDecision(id); setTimeout(() => document.getElementById('bd-detail')?.scrollIntoView({block:'start'}),300); }
  function consoleExportEvidence() {
    if (!investigationContext) return;
    const blob = new Blob([JSON.stringify(investigationContext,null,2)],{type:'application/json'});
    const url = URL.createObjectURL(blob), anchor = document.createElement('a');
    anchor.href = url; anchor.download = 'alert-' + investigationContext.alert.id + '-evidence.json'; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url),1000);
  }
  function consoleAnalystAction(action, ids) {
    const targets = Array.isArray(ids) ? ids : investigationContext ? [investigationContext.alert.id] : [];
    if (!targets.length) { SOCUI.notify('Select at least one editable alert.'); return; }
    investigationAction = {action, ids:[...targets]};
    const dialog = document.getElementById('analyst-action-dialog');
    document.getElementById('analyst-action-title').textContent = action === 'CLOSED' ? 'Close alerts with evidence' : action === 'ACK' ? 'Acknowledge alerts' : 'Record analyst verdict';
    document.getElementById('analyst-action-description').textContent = `${action} · ${targets.length} alert(s): ${targets.map(id => '#' + id).join(', ')}`;
    document.getElementById('analyst-action-reason').value = '';
    document.getElementById('analyst-action-error').textContent = '';
    document.getElementById('analyst-action-submit').disabled = false;
    if (!dialog.open) dialog.showModal();
  }
  function consoleCancelAction() { document.getElementById('analyst-action-dialog')?.close(); investigationAction = null; }
  async function consoleSubmitAnalystAction(event) {
    event.preventDefault();
    if (!investigationAction) return;
    const {action,ids} = investigationAction;
    const reason = document.getElementById('analyst-action-reason').value.trim();
    if (reason.length < 3) return;
    const button = document.getElementById('analyst-action-submit'); button.disabled = true;
    const verdict = ['TRUE_POSITIVE','FALSE_POSITIVE'].includes(action);
    const results = [];
    // Snapshot selection, bounded requests, explicit partial failures.
    for (const id of ids.slice(0,100)) {
      try {
        await SOCUI.request(`/api/alerts/${id}/${verdict ? 'verdict' : 'status'}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(verdict ? {verdict:action,reason} : {status:action,note:reason})});
        results.push({id,ok:true});
      } catch (error) { results.push({id,ok:false,error:error.message}); }
    }
    button.disabled = false;
    const failed = results.filter(r => !r.ok);
    if (failed.length) { document.getElementById('analyst-action-error').textContent = `${results.length-failed.length} saved; failed: ${failed.map(r => '#' + r.id + ' ' + r.error).join('; ')}`; investigationAction = {action,ids:failed.map(r => r.id)}; }
    else { consoleCancelAction(); SOCUI.notify(`${results.length} analyst action(s) recorded with audit notes.`); }
    if (typeof consoleClearSelection === 'function') consoleClearSelection(results.filter(r => r.ok).map(r => r.id));
    if (SOCUI.currentPanel === 'alerts') consoleLoadQueue(true);
    if (investigationContext && !failed.length) consoleOpenInvestigation(investigationContext.alert.id);
    consoleLoadSummary(true);
  }
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('analyst-action-form')?.addEventListener('submit',consoleSubmitAnalystAction);
    document.getElementById('investigation-drawer')?.addEventListener('close', () => {
      investigationVersion++;
      if (investigationReturnFocus?.isConnected) investigationReturnFocus.focus();
      else {
        const id = investigationReturnFocus?.closest?.('[data-alert-id]')?.dataset.alertId;
        if (id) Array.from(document.querySelectorAll('tr[data-alert-id="' + Number(id) + '"]')).find(row => row.getClientRects().length)?.focus();
      }
    });
  });
  Object.assign(window, {consoleAnalystAction, consoleAskCopilot, consoleCancelAction,
    consoleCloseInvestigation, consoleExportEvidence, consoleInvestigationTab,
    consoleOpenInvestigation, consolePivotIncident, consolePivotReplay, consolePivotTechnique});
})();
