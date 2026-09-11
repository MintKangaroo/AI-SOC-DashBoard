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
      document.getElementById('quality-scope').textContent = `${data.generated_at} · 최근 ${data.hours}시간 · 알림 ${SOCUI.number(data.total)}건 중 ${SOCUI.number(data.sample_size)}건 분석${data.truncated ? ' · 표본 제한, 전체 이력 아님' : ''}. ${data.definition}`;
      box.innerHTML = data.rules.map(rule => `<tr><td>${SOCUI.entity(rule.rule)}</td><td>${SOCUI.number(rule.total)}</td><td>${SOCUI.number(rule.tp)}</td><td>${SOCUI.number(rule.fp)}</td><td>${SOCUI.number(rule.unreviewed)}</td><td>${rule.fp_rate == null ? '판정 없음' : rule.fp_rate + '%'}</td><td><span class="confidence-bars" role="img" aria-label="신뢰도 구간 0–20, 20–40, 40–60, 60–80, 80–100%: ${rule.confidence.join(', ')}">${rule.confidence.map(n => `<i style="height:${Math.max(2,Math.round(n/Math.max(...rule.confidence,1)*25))}px" title="${n}건"></i>`).join('')}</span></td><td>${Object.entries(rule.provenance).map(([state,count]) => `${SOCUI.provenance({provenance:{state}})} ${SOCUI.number(count)}`).join(' ')}</td></tr>`).join('') || '<tr><td colspan="8"><div class="console-empty">이 기간에 저장된 알림 없음.</div></td></tr>';
      document.getElementById('quality-trend').innerHTML = '<table class="console-table"><thead><tr><th>탐지 일자</th><th>정탐</th><th>오탐</th><th>미검토</th><th>오탐율</th></tr></thead><tbody>' + (data.trend || []).map(day => `<tr><td>${escapeHtml(day.date)}</td><td>${day.tp}</td><td>${day.fp}</td><td>${day.unreviewed}</td><td>${day.fp_rate == null ? '—' : day.fp_rate + '%'}</td></tr>`).join('') + '</tbody></table>';
      document.getElementById('quality-sources').innerHTML = (data.sources || []).map(source => `<div class="sensor-row">${SOCUI.entity(source.source)}<strong>${SOCUI.number(source.count)}</strong></div>`).join('') || '<p class="text-muted">소스 집계 없음.</p>';
      const d = data.dedup;
      document.getElementById('quality-dedup').innerHTML = d ? `<p class="text-muted">처리 카운터 측정값 · 현재 프로세스 기준 · 입력 출처 혼합</p><dl class="evidence-fields">${[['평가',d.seen],['중복 병합',d.deduplicated],['억제',d.suppressed],['스톰',d.storms]].map(([label,value]) => `<div class="evidence-field"><dt>${label}</dt><dd>${SOCUI.number(value)}</dd></div>`).join('')}</dl><p class="text-muted mt-3">실제 룰 변경은 이 미리보기와 별개입니다. 원본 이벤트는 억제 저장소에 남습니다.</p>` : '<p>중복제거 카운터 없음.</p>';
    } catch (error) { document.getElementById('quality-scope').textContent = error.message; }
  }
  async function consolePreviewSuppression() {
    const box = document.getElementById('quality-preview');
    if (!box) return;
    const body = {rule:document.getElementById('quality-rule').value.trim(),source_prefix:document.getElementById('quality-source').value.trim(),threat_type:document.getElementById('quality-type').value.trim()};
    if (!Object.values(body).some(Boolean)) { box.textContent = '조건을 하나 이상 입력하세요.'; return; }
    box.textContent = '과거 표본 평가 중…';
    try {
      const result = await SOCUI.request('/api/console/suppression-preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      box.innerHTML = `<div class="workspace-context"><strong>억제 예상 ${SOCUI.number(result.would_suppress)}건 · CRITICAL 면제 ${SOCUI.number(result.critical_exempt)}건</strong><br/>24시간 ${SOCUI.number(result.total)}건 중 ${SOCUI.number(result.examined)}건 검사${result.truncated ? ' · 표본' : ''}.<br/>${escapeHtml(result.explanation)}</div>` + result.alert_ids.slice(0,20).map(id => `<button class="btn btn-xs btn-outline-secondary m-1" ${act('consoleOpenInvestigation',[id])}>알림 #${id}</button>`).join('');
    } catch (error) { box.textContent = error.message; }
  }
  Object.assign(window, {consoleLoadQuality, consolePreviewSuppression});
})();
