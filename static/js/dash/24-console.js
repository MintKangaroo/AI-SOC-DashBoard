/* Global shell, measured situation summary and keyboard command palette. */
(function () {
  let consoleSnapshot = null;
  let consoleSummaryBusy = false;
  let consoleActivityChart = null;
  let consolePaletteVersion = 0;
  let consolePaletteTimer = null;
  let consolePaletteFocus = null;
  const consoleSensorNames = {packet_analyzer:'패킷 캡처', sysmon_parser:'Sysmon', edr:'EDR 엔드포인트',
    siem_collector:'SIEM 로그 수집', authlog:'SSH 인증', syslog_receiver:'Syslog 수신',
    snort:'Snort IDS', suricata:'Suricata IDS', zeek:'Zeek NSM'};
  const consolePanelNotes = {
    ml: ['EXPERIMENTAL', 'Isolation Forest 판정은 참고용입니다. 학습 데이터 출처는 모델과 함께 표시됩니다. RF·LSTM·Q-learning 은 격리된 실험이며, 유효한 평가 없이는 정확도를 주장하지 않습니다.'],
    mitre: ['MIXED', '룰 존재·퍼플팀 검증·관측 히트는 서로 다른 신호입니다. 히트 카운터는 혼합 출처와 현재 프로세스 이력을 포함하며, 운영 가시성을 증명하지 않습니다.'],
    campaigns: ['MIXED', '상관관계는 같은 출발지와 시간에 근거한 가설이지 공격자 귀속이 아닙니다. 결론을 내리기 전에 구성 알림과 출처를 확인하세요.'],
    'siem-correlation': ['MIXED', '상관 규칙은 새 탐지를 만들어 냅니다. 대응 전에 독립 근거와 알림별 출처를 검토하세요.'],
    soar: ['SIMULATED', '아래의 실제 대응 모드와 승인 게이트를 확인하세요. 게이트 통과는 자격 요건 충족이지 방화벽 조작 성공의 증명이 아닙니다. 재현은 대응 상태를 바꾸지 않습니다.'],
    vulnscan: ['UNAVAILABLE', '자산 → 서비스 → CVE 매칭 → 검증 → 패치 상태. 스캐너 매칭은 교차 검증 전까지 미확인이며, 패치 상태 불명은 확인된 취약점이 아닙니다.'],
    patch: ['UNAVAILABLE', '탐지된 패키지와 제안된 변경을 먼저 검토하세요. 기본은 dry-run 이며 결과마다 실행 모드를 확인하세요. 실제 적용은 서버 정책 게이트를 거칩니다.'],
    purple: ['SIMULATED', '검증은 모의 공격으로 실제 탐지 엔진을 돌립니다. 테스트 커버리지는 실환경 탐지 정확도가 아닙니다.'],
    health: ['REAL', '프로세스와 모듈 상태 측정값입니다. 라이브러리가 살아 있다고 센서가 살아 있는 것은 아닙니다. 지연·마지막 이벤트·적체 지표가 없으면 없음으로 표시합니다.'],
    metrics: ['MIXED', 'MTTA/MTTR 은 기록된 인시던트 전이에서 계산합니다. 자동 오탐 종결 비율은 분석가 오탐율이나 AI 정확도가 아니며, 지표에 데모·과거 인시던트가 섞여 있을 수 있습니다.'],
    siem: ['MIXED', '보관 중인 SIEM 이벤트 버퍼를 텍스트나 field=value 로 검색합니다. 시간 필터는 이벤트 시각 기준입니다. 알림 조사와 저장된 헌팅은 아카이브 알림을 포함합니다.'],
    hunt: ['MIXED', '저장된 헌팅은 아카이브를 포함한 알림 이력을 조회합니다. 델타는 마지막 실행 이후 건수입니다. IOC 로 승격하기 전에 출처를 확인하세요.'],
    labeling: ['MIXED', '개별 분석가 라벨과 더 약한 그룹 라벨을 구분합니다. 합성·미검증 기록은 실환경 평가 근거로 쓰지 않습니다.'],
    'alert-history': ['MIXED', '활성·아카이브 증거를 함께 조회합니다. 기록을 열면 조사 맥락을 볼 수 있으며, 아카이브 기록은 읽기 전용입니다.'],
    reputation: ['UNAVAILABLE', '평판 제공자를 쓸 수 없으면 데모 폴백을 사용할 수 있습니다. 평판 점수만으로는 침해의 근거가 되지 않습니다.'],
    report: ['UNAVAILABLE', '브리핑은 참고용 요약입니다. 공유 전에 증거 참조와 모델/데이터 모드를 확인하세요.'],
  };

  function consoleSetText(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }
  function consoleToggleLive() { SOCRealtime.setPaused(!SOCRealtime.paused); }
  function consoleChangeRange(el) {
    SOCUI.hours = Number(el.value);
    consoleLoadSummary(true);
    if (SOCUI.currentPanel === 'alerts') consoleLoadQueue(true);
    if (SOCUI.currentPanel === 'quality') consoleLoadQuality();
    SOCUI.notify('시간 범위가 관제 센터·알림 큐·개체 검색·탐지 품질에 적용되었습니다. 전문 패널은 각자 범위를 씁니다.');
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
      consoleSetText('cc-case-scope', (caseSources.length === 1 ? caseSources[0] : caseSources.length ? 'MIXED' : '인시던트 없음') + ' · 현재 인시던트 / 기간 무관');
      consoleSetText('cc-high', SOCUI.number(high));
      consoleSetText('cc-open', SOCUI.number(data.queue.total));
      consoleSetText('cc-campaigns', SOCUI.number(data.campaigns.count));
      consoleSetText('cc-campaign-scope', data.campaigns.truncated ? '표본: 최근 5,000건' : '관측된 그룹 · 공격자 귀속 아님');
      consoleSetText('cc-blocks', SOCUI.number(data.response.active_blocks));
      consoleSetText('cc-block-mode', data.response.mode === 'simulate' ? 'SIMULATED · 방화벽 미실행' : data.response.mode.toUpperCase() + ' · 기록된 활성 차단');
      consoleSetText('cc-sensors', real + ' / ' + sensors.length);
      consoleSetText('console-sensor-count', real + '/' + sensors.length);
      consoleSetText('console-situation', data.queue.total ? `미처리 알림 ${SOCUI.number(data.queue.total)}건 검토 필요` : '선택 기간에 미처리 알림 없음');
      consoleSetText('console-situation-detail', `실센서 ${real}개 · 오프라인/비활성 ${unavailable}개 · 조용하다고 결론짓기 전에 가시성을 확인하세요.`);
      consoleSetText('console-updated', '스냅샷 ' + data.generated_at + ' · 서버 시간');
      const prov = [...new Set(data.activity.counts.map(c => c.provenance))];
      consoleSetText('console-data-label', prov.length === 1 ? prov[0] : prov.length ? 'MIXED SOURCES' : '알림 데이터 없음');
      const label = document.getElementById('console-data-label');
      if (label) label.className = 'provenance provenance-' + (prov.length === 1 ? prov[0].toLowerCase() : 'mixed');
      consolePaintPriority(data.queue.alerts.slice(0, 6));
      const sensorBox = document.getElementById('console-sensors');
      if (sensorBox) sensorBox.innerHTML = sensors.map(m => {
        const label = {real:'LIVE · REAL',demo:'DEMO',down:'OFFLINE',off:'OFF',live:'서비스만'}[m.mode] || 'UNAVAILABLE';
        return `<div class="sensor-row"><span>${consoleSensorNames[m.key]}</span><span class="sensor-state ${m.mode === 'real' ? 'live' : m.mode}"><i class="status-dot"></i>${label}</span></div>`;
      }).join('');
      const response = document.getElementById('console-response');
      const mode = data.response.mode === 'simulate' ? 'SIMULATED' : 'REAL';
      if (response) response.innerHTML = `${SOCUI.provenance({provenance:{state:mode}})}<p><strong>${data.response.approval_required ? '수동 승인 필요' : '승인 정책: 자동'}</strong></p><p>최근 실행 중 승인 대기 ${SOCUI.number(data.response.approvals.length)}건<br/>신뢰도 임계값 ${escapeHtml(String(data.response.min_confidence))}% · 차단 유지 ${escapeHtml(String(data.response.ttl_hours))}시간</p><p>사설망·자기 IP 보호는 계속 적용됩니다.</p>`;
      const cases = document.getElementById('console-cases');
      if (cases) cases.innerHTML = data.incidents.recent.map(inc => `<button class="console-case" ${act('openIncident',[inc.id])}><strong>#${inc.id} · ${escapeHtml(inc.title)}</strong><small>${sevBadge(inc.severity)} ${SOCUI.provenance(inc)} · ${escapeHtml(inc.status)}</small></button>`).join('') || '<div class="console-empty">진행 중 인시던트 없음.</div>';
      const pipeline = document.getElementById('console-pipeline');
      if (pipeline) {
        const tel = data.telemetry, points = tel.points || [], probes = tel.probes || [];
        const warnings = points.filter(p => p.slow || p.errors).map(p => p.name + ': p95 ' + p.p95 + 'ms · 오류 ' + p.errors + '건').concat(probes.filter(p => p.warn || p.error).map(p => p.label + ': ' + (p.error ? '프로브 없음' : p.value + ' ' + p.unit)));
        const search = points.find(p => p.name === 'console.search');
        const queue = probes.find(p => p.name === 'ai.queue_depth');
        pipeline.innerHTML = `<span class="provenance provenance-real">MEASURED</span><p class="mt-2">${warnings.length ? warnings.map(escapeHtml).join('<br/>') : points.length ? '텔레메트리 임계값 초과 없음.' : '측정 표본 없음.'}</p><p class="text-muted small">검색 p95: ${search ? escapeHtml(String(search.p95)) + 'ms' : '없음'}<br/>AI 큐: ${queue?.value != null ? SOCUI.number(queue.value) : '없음'}<br/>측정값에 데모 부하가 포함됩니다.</p>`;
      }
      consolePaintActivity(data.activity);
      consoleApplyPanelContext(SOCUI.currentPanel);
    } catch (error) {
      consoleSetText('console-situation', '운영 스냅샷을 가져오지 못함');
      consoleSetText('console-situation-detail', '마지막 표시 값이 오래됐을 수 있습니다. ' + error.message);
    } finally { consoleSummaryBusy = false; if (hours !== SOCUI.hours) consoleLoadSummary(true); }
  }

  function consolePaintPriority(alerts) {
    const box = document.getElementById('console-priority');
    if (!box) return;
    if (!alerts.length) { box.innerHTML = '<tr><td colspan="6"><div class="console-empty">이 기간에 미처리 알림이 없습니다. 활동이 없다고 결론짓기 전에 센서 커버리지를 확인하세요.</div></td></tr>'; return; }
    // Keep the row under the pointer/focus. New snapshots do not sort live rows.
    const current = Array.from(box.querySelectorAll('[data-alert-id]')).map(el => Number(el.dataset.alertId));
    const stable = [...alerts].sort((a,b) => {
      const ai = current.indexOf(a.id), bi = current.indexOf(b.id);
      return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi);
    });
    reconcileList(box, stable, a => a.id, a => `<tr data-alert-id="${a.id}" tabindex="0" role="button" aria-label="알림 ${a.id} 조사" ${act('consoleOpenInvestigation',[a.id])}><td>${sevBadge(a.severity)}</td><td><span class="detection-title">${escapeHtml(a.description || a.threat_type)}</span><span class="detection-meta">#${a.id} · ${SOCUI.entity(a.src_ip)} ${a.dst_ip ? ' → ' + SOCUI.entity(a.dst_ip) : ''}</span></td><td>${SOCUI.confidence(a)}</td><td>${SOCUI.provenance(a)}</td><td class="text-nowrap">${escapeHtml((a.timestamp || '').slice(11))}</td><td><i class="fa fa-angle-right text-muted"></i></td></tr>`);
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
    const description = `저장 알림 ${SOCUI.number(activity.total)}건 · ` + (Object.entries(counts).map(([p,n]) => `${p} ${SOCUI.number(n)}`).join(' · ') || '이 기간에 기록된 이벤트 없음.');
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
      const summary = document.createElement('summary'); summary.textContent = header?.textContent.trim() || '패널 안내';
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
    SOCUI.notify('알림은 기록된 분석가 큐와 대응 승인을 사용합니다. 별도의 알림함은 없습니다.');
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
    let html = '<div class="palette-group-label">이동</div>' + nav.slice(0, q ? 12 : 6).map(el => `<button class="palette-result" ${act('consolePaletteNavigate',[el.dataset.panel])}><i class="fa fa-arrow-turn-down fa-rotate-270"></i><span>${escapeHtml(el.querySelector('span')?.textContent || el.textContent)}</span></button>`).join('');
    const commands = [['실시간 표시 일시정지',true],['실시간 표시 재개',false]].filter(([label]) => !q || label.toLowerCase().includes(q));
    html += commands.map(([label, paused]) => `<button class="palette-result" ${act('consolePaletteRealtime',[paused])}><i class="fa fa-pause"></i>${label}</button>`).join('');
    if (!q || 'critical 만 보기 view critical only'.includes(q)) html += `<button class="palette-result" ${act('consolePaletteCritical')}>CRITICAL 만 보기</button>`;
    box.innerHTML = html;
    if (q.length < 2) { consoleSelectPalette(0); return; }
    box.insertAdjacentHTML('beforeend', '<div id="palette-loading" class="console-empty">저장된 증거 검색 중…</div>');
    try {
      const data = await SOCUI.request('/api/console/entities?' + new URLSearchParams({q:query,hours:SOCUI.hours}));
      if (version !== consolePaletteVersion) return;
      for (const group of data.groups) {
        if (!group.items.length) continue;
        html += `<div class="palette-group-label">${escapeHtml({Alerts:'알림',Incidents:'인시던트',IOCs:'IOC'}[group.type] || group.type)} ${group.type === 'Alerts' ? '· ' + SOCUI.number(data.total_alerts) + '건' : ''}</div>`;
        html += group.items.map(item => group.type === 'Alerts'
          ? `<button class="palette-result" ${act('consolePaletteAlert',[item.id])}>${sevBadge(item.severity)}<span>#${item.id} · ${escapeHtml(item.threat_type)}<small>${escapeHtml(item.src_ip || '')} · ${escapeHtml(item.timestamp)}</small></span>${SOCUI.provenance(item)}</button>`
          : group.type === 'Incidents'
            ? `<button class="palette-result" ${act('consolePaletteIncident',[item.id])}><i class="fa fa-folder-open"></i><span>#${item.id} ${escapeHtml(item.title)}<small>${escapeHtml(item.status)}</small></span></button>`
            : `<button class="palette-result" ${act('consolePaletteNavigate',['watchlist'])}><i class="fa fa-fingerprint"></i><span>${escapeHtml(item.value)}<small>${escapeHtml(item.type)} · ${escapeHtml(item.note || '')}</small></span></button>`).join('');
      }
      if (!data.groups.some(g => g.items.length)) html += '<div class="console-empty">이 기간에 일치하는 증거가 없습니다.<br/>기간을 늘리거나 알림 이력을 열어 보세요.</div>';
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
      consoleSetText('console-pending', state.paused ? `+${SOCUI.number(state.pending)}건 새 이벤트${state.omitted ? ' · 버퍼 상한 도달' : ''} · 재개` : '화면 갱신 일시정지');
    });
    socket.on('connect', () => { SOCRealtime.changed(); consoleLoadSummary(true); });
    socket.on('disconnect', () => { consoleSetText('badge-status','DISCONNECTED'); consoleSetText('console-updated','연결 끊김 · 표시된 스냅샷이 오래됐을 수 있음'); });
    const disclosure = document.getElementById('overview-map');
    disclosure?.addEventListener('toggle', () => { if (disclosure.open) initMap(); });
    document.getElementById('evidence-summary')?.addEventListener('toggle', event => {
      if (event.target.open) consoleActivityChart?.resize();
    });
    SOCUI.request('/api/whoami').then(data => {
      consoleSetText('console-environment',data.demo ? 'DEMO 환경' : 'REAL 환경');
      consoleSetText('console-user-name',data.user || (data.auth_enabled ? '분석가' : '로컬 작업공간 · 인증 꺼짐'));
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
