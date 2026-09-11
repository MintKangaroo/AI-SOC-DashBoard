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
    document.getElementById('investigation-title').textContent = '저장된 증거 불러오는 중…';
    document.getElementById('investigation-reference').textContent = '알림 #' + id;
    document.getElementById('investigation-meta').textContent = '';
    document.getElementById('investigation-content').innerHTML = '<div class="console-empty">알림·증거·결정·감사 이력을 가져오는 중…</div>';
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
      document.getElementById('investigation-reference').textContent = `알림 #${alert.id} / ${context.storage}`;
      document.getElementById('investigation-meta').innerHTML = `${sevBadge(alert.severity)} ${SOCUI.provenance(alert)} <span>${escapeHtml(alert.status)}</span><span>신뢰도 ${SOCUI.confidence(alert)}</span><span>${escapeHtml(alert.timestamp)} · 서버 시간</span>`;
      document.getElementById('investigation-actions').innerHTML = alert.archived
        ? '<span class="text-muted">아카이브 증거는 읽기 전용입니다. 저장된 헌팅을 쓰거나 라벨링 패널에서 개별 라벨을 추가하세요.</span>'
        : `<button class="btn btn-sm btn-cyan" ${act('consoleAnalystAction',['ACK'])}>확인(ACK)</button><button class="btn btn-sm btn-outline-secondary" ${act('consoleAnalystAction',['TRUE_POSITIVE'])}>정탐</button><button class="btn btn-sm btn-outline-secondary" ${act('consoleAnalystAction',['FALSE_POSITIVE'])}>오탐</button><button class="btn btn-sm btn-outline-secondary" ${act('consoleAnalystAction',['CLOSED'])}>사유 입력 후 종료</button><button class="btn btn-sm btn-outline-secondary ms-auto" ${act('consoleExportEvidence')}>증거 내보내기</button>`;
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
  const investigationStages = {'DETECTED':'탐지','AI TRIAGED':'AI 트리아지','SOAR DECISION':'SOAR 결정','ANALYST ACTION':'분석가 조치','INCIDENT':'인시던트'};
  function investigationStage(stage) { return investigationStages[stage] || stage; }
  function investigationRaw(value) { return `<pre class="raw-evidence">${escapeHtml(JSON.stringify(value, null, 2))}</pre>`; }
  function consoleRenderInvestigation() {
    const box = document.getElementById('investigation-content');
    const context = investigationContext;
    if (!context || !box) return;
    const alert = context.alert, details = context.evidence;
    if (investigationTab === 'evidence') {
      const fields = [['출발지',alert.src_ip],['목적지',alert.dst_ip],['자산 / 호스트',details.hostname || details.host || details.computer],['프로세스',details.process || details.image || details.cmdline],['사용자',details.user || details.username],['탐지 룰',details.rule_id || details.sid || details.rule || details.signature_id],['소스',details.source || details.siem_source || details.sensor],['담당자',alert.assignee],['분석가 판정',alert.verdict],['판정 사유',alert.verdict_reason]];
      box.innerHTML = `<section class="investigation-section"><h3>탐지 증거</h3><p>${escapeHtml(alert.description || '설명 미기록.')}</p><dl class="evidence-fields">${fields.map(([key,value]) => `<div class="evidence-field"><dt>${key}</dt><dd>${['출발지','목적지','자산 / 호스트','사용자','탐지 룰'].includes(key) && value ? SOCUI.entity(value) : escapeHtml(String(value || '미기록'))}</dd></div>`).join('')}</dl></section><section class="investigation-section"><h3>출처</h3><p>${SOCUI.provenance(alert)} ${escapeHtml(alert.provenance.reason)}</p></section><section class="investigation-section"><h3>ATT&CK 매핑</h3>${context.techniques.map(t => `<button class="btn btn-sm btn-outline-secondary me-2 mb-2" ${act('consolePivotTechnique',[String(t.technique)])}>${escapeHtml(String(t.technique))} · ${escapeHtml(t.basis)}</button>`).join('') || '<p>기법 매핑 없음.</p>'}</section><section class="investigation-section"><h3>원본 · 정규화 증거</h3>${investigationRaw(details)}</section><section class="investigation-section"><h3>관련 알림</h3><p>7일 내 같은 출처의 최신 일치 건입니다. 같은 개체를 공유한다는 것은 조사 단서이지 한 공격의 증명이 아닙니다.</p>${context.related_alerts.map(a => `<button class="console-case" ${act('consoleOpenInvestigation',[a.id])}><strong>#${a.id} ${escapeHtml(a.threat_type)}</strong><small>${sevBadge(a.severity)} ${SOCUI.provenance(a)} ${escapeHtml(a.timestamp)}</small></button>`).join('') || '<p>관련 알림 없음.</p>'}</section><section class="investigation-section"><h3>연결된 인시던트</h3>${context.incidents.map(i => `<button class="console-case" ${act('consolePivotIncident',[i.id])}>#${i.id} ${escapeHtml(i.title)} · ${escapeHtml(i.status)}</button>`).join('') || '<p>이 알림에 연결된 인시던트 없음.</p>'}</section>`;
    } else if (investigationTab === 'timeline') {
      box.innerHTML = `<section class="investigation-section"><h3>기록된 순서</h3><p>시각이 기록된 증거만 타임라인에 놓입니다. 보강·상관·종결 시각이 없으면 추정하지 않습니다.</p><ol class="evidence-timeline">${context.timeline.map(e => `<li><strong>${escapeHtml(investigationStage(e.stage))}</strong><time>${escapeHtml(e.timestamp || '시각 없음')}</time><p>${escapeHtml(e.text || '')}</p><small class="text-muted">${escapeHtml(e.reference)}</small></li>`).join('')}</ol></section>`;
    } else if (investigationTab === 'copilot') {
      box.innerHTML = `<section class="investigation-section"><h3>분석 코파일럿 · 알림 #${alert.id}</h3><p>사실은 저장된 증거에서 구성됩니다. 모델 출력은 참고용이며, 대화로 차단·패치·프로세스 종료를 실행할 수 없습니다.</p><div class="copilot-intents">${['증거 요약','조사 단계 제안','대응 결정 설명','인계 요약 생성'].map(intent => `<button class="btn btn-sm btn-outline-secondary" ${act('consoleAskCopilot',[intent])}>${intent}</button>`).join('')}</div><div id="investigation-brief">${consoleBriefHtml(investigationBrief)}</div></section><section class="investigation-section"><h3>보관된 트리아지 결과</h3><p>모델의 결론이며 분석가 판정이나 원본 증거가 아닙니다.</p>${context.ai.map(item => `<details class="mb-3"><summary>${escapeHtml(item.timestamp)} · ${escapeHtml(item.model)} ${item.model === 'demo' ? SOCUI.provenance({origin:'demo'}) : ''}</summary>${investigationRaw(item.result)}</details>`).join('') || '<p>보관된 트리아지 결과 없음.</p>'}</section>`;
    } else {
      box.innerHTML = `<section class="investigation-section"><h3>시스템은 왜 대응했나?</h3><p>기록된 게이트 판정과 불변 입력값입니다. 게이트 통과만으로 대응 성공이 증명되지는 않습니다.</p>${context.decisions.map(record => `<div class="console-card mb-3"><div class="console-card-heading"><h2>결정 #${record.id}</h2>${SOCUI.provenance({provenance:{state:record.thresholds?.block_mode === 'simulate' ? 'SIMULATED' : record.thresholds?.block_mode ? 'REAL' : 'UNAVAILABLE'}})}<span class="ms-auto">${escapeHtml(record.outcome_label || record.outcome || '결과 없음')}</span></div><div class="console-card-body"><p>${escapeHtml(record.ts)} · ${escapeHtml(record.reason || '')}</p><div class="response-gates">${record.gates.map(g => `<div class="response-gate ${g.passed ? 'passed' : ''}"><span>${g.passed ? 'PASS' : 'HOLD'}</span><div>${escapeHtml(g.label || g.id)}<small>관측: ${escapeHtml(JSON.stringify(g.actual))} · 요구: ${escapeHtml(JSON.stringify(g.required))}</small></div></div>`).join('')}</div><details class="mt-3"><summary>불변 결정 입력값</summary>${investigationRaw(record.signals)}</details><button class="btn btn-sm btn-outline-secondary mt-3" ${act('consolePivotReplay',[record.id])}>재현(시뮬레이션) 열기</button></div></div>`).join('') || '<p>이 알림에 연결된 SOAR 결정 없음.</p>'}</section><section class="investigation-section"><h3>분석가 감사 이력</h3>${context.audit.map(e => `<div class="console-case"><strong>${escapeHtml(e.action)} · ${escapeHtml(e.actor)}</strong><small>${escapeHtml(e.ts)}</small><p>${escapeHtml(e.detail)}</p></div>`).join('') || '<p>이 알림에 연결된 감사 기록 없음.</p>'}</section>`;
    }
  }
  function consoleBriefHtml(brief) {
    if (!brief) return '<div class="console-empty">브리핑 없음.</div>';
    return `<div class="workspace-context">${brief.generated ? 'AI 참고 의견 · 모델 추론은 검증 필요' : '증거 요약 · 생성이 아닌 결정적 구성'}</div>` + [['facts','사실'],['inferences','추론'],['recommendations','권고'],['unknowns','미확인 / 누락 데이터']].map(([key,label]) => `<section class="brief-section"><h3>${label}</h3><ul>${(brief[key]?.length ? brief[key] : ['기록 없음.']).map(line => `<li>${escapeHtml(line)}</li>`).join('')}</ul></section>`).join('');
  }
  async function consoleAskCopilot(intent) {
    if (!investigationContext) return;
    const sequence = ++investigationCopilotRequest;
    const id = investigationContext.alert.id, version = investigationVersion;
    document.querySelectorAll('.copilot-intents button').forEach(button => { button.disabled = true; });
    const box = document.getElementById('investigation-brief');
    if (box) box.innerHTML = '<div class="console-empty">증거 기반 브리핑 준비 중…</div>';
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
    if (!targets.length) { SOCUI.notify('편집 가능한 알림을 하나 이상 선택하세요.'); return; }
    investigationAction = {action, ids:[...targets]};
    const dialog = document.getElementById('analyst-action-dialog');
    document.getElementById('analyst-action-title').textContent = action === 'CLOSED' ? '근거를 남기고 알림 종료' : action === 'ACK' ? '알림 확인(ACK)' : '분석가 판정 기록';
    document.getElementById('analyst-action-description').textContent = `${action} · 알림 ${targets.length}건: ${targets.map(id => '#' + id).join(', ')}`;
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
    if (failed.length) { document.getElementById('analyst-action-error').textContent = `${results.length-failed.length}건 저장 · 실패: ${failed.map(r => '#' + r.id + ' ' + r.error).join('; ')}`; investigationAction = {action,ids:failed.map(r => r.id)}; }
    else { consoleCancelAction(); SOCUI.notify(`분석가 조치 ${results.length}건이 감사 메모와 함께 기록되었습니다.`); }
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
