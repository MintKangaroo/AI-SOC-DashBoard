/* Detection quality: human verdict denominators and a non-mutating preview. */
(function () {
  let qualityRequestVersion = 0;
  async function consoleLoadQuality() {
    const box = document.getElementById('quality-rows');
    if (!box) return;
    const version = ++qualityRequestVersion;
    try {
      const data = await SOCUI.request('/api/console/quality?hours=' + SOCUI.hours);
      if (version !== qualityRequestVersion) return;
      document.getElementById('quality-scope').textContent = `${data.generated_at} · Last ${data.hours}h · ${SOCUI.number(data.sample_size)} of ${SOCUI.number(data.total)} alerts analyzed${data.truncated ? ' · BOUNDED SAMPLE, not the entire history' : ''}. ${data.definition}`;
      box.innerHTML = data.rules.map(rule => `<tr><td>${SOCUI.entity(rule.rule)}</td><td>${SOCUI.number(rule.total)}</td><td>${SOCUI.number(rule.tp)}</td><td>${SOCUI.number(rule.fp)}</td><td>${SOCUI.number(rule.unreviewed)}</td><td>${rule.fp_rate == null ? 'Unavailable · no verdicts' : rule.fp_rate + '%'}</td><td><span class="confidence-bars" role="img" aria-label="Confidence bins 0–20, 20–40, 40–60, 60–80, 80–100 percent: ${rule.confidence.join(', ')}">${rule.confidence.map(n => `<i style="height:${Math.max(2,Math.round(n/Math.max(...rule.confidence,1)*25))}px" title="${n} alerts"></i>`).join('')}</span></td><td>${Object.entries(rule.provenance).map(([state,count]) => `${SOCUI.provenance({provenance:{state}})} ${SOCUI.number(count)}`).join(' ')}</td></tr>`).join('') || '<tr><td colspan="8"><div class="console-empty">No stored alerts in this range.</div></td></tr>';
      document.getElementById('quality-trend').innerHTML = '<table class="console-table"><thead><tr><th>Detection date</th><th>TP</th><th>FP</th><th>Unreviewed</th><th>FP rate</th></tr></thead><tbody>' + (data.trend || []).map(day => `<tr><td>${escapeHtml(day.date)}</td><td>${day.tp}</td><td>${day.fp}</td><td>${day.unreviewed}</td><td>${day.fp_rate == null ? 'Unavailable' : day.fp_rate + '%'}</td></tr>`).join('') + '</tbody></table>';
      document.getElementById('quality-sources').innerHTML = (data.sources || []).map(source => `<div class="sensor-row">${SOCUI.entity(source.source)}<strong>${SOCUI.number(source.count)}</strong></div>`).join('') || '<p class="text-muted">No source counts recorded.</p>';
      const d = data.dedup;
      document.getElementById('quality-dedup').innerHTML = d ? `<p class="text-muted">Measured processing counters · current process lifetime · mixed input provenance</p><dl class="evidence-fields">${[['Evaluated',d.seen],['Deduplicated',d.deduplicated],['Suppressed',d.suppressed],['Storms',d.storms]].map(([label,value]) => `<div class="evidence-field"><dt>${label}</dt><dd>${SOCUI.number(value)}</dd></div>`).join('')}</dl><p class="text-muted mt-3">Changing live rules is separate from this preview. Original events remain in the suppression store.</p>` : '<p>Deduplication counters unavailable.</p>';
    } catch (error) { document.getElementById('quality-scope').textContent = error.message; }
  }
  async function consolePreviewSuppression() {
    const box = document.getElementById('quality-preview');
    if (!box) return;
    const body = {rule:document.getElementById('quality-rule').value.trim(),source_prefix:document.getElementById('quality-source').value.trim(),threat_type:document.getElementById('quality-type').value.trim()};
    if (!Object.values(body).some(Boolean)) { box.textContent = 'Enter at least one preview criterion.'; return; }
    box.textContent = 'Evaluating the historical sample…';
    try {
      const result = await SOCUI.request('/api/console/suppression-preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      box.innerHTML = `<div class="workspace-context"><strong>${SOCUI.number(result.would_suppress)} would be suppressed · ${SOCUI.number(result.critical_exempt)} CRITICAL exempt</strong><br/>${SOCUI.number(result.examined)} of ${SOCUI.number(result.total)} examined over 24h${result.truncated ? ' · sampled' : ''}.<br/>${escapeHtml(result.explanation)}</div>` + result.alert_ids.slice(0,20).map(id => `<button class="btn btn-xs btn-outline-secondary m-1" ${act('consoleOpenInvestigation',[id])}>Alert #${id}</button>`).join('');
    } catch (error) { box.textContent = error.message; }
  }
  Object.assign(window, {consoleLoadQuality, consolePreviewSuppression});
})();
