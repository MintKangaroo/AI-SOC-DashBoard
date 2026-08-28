/* dashboard/02-overview.js — 개요 차트·핵심 소켓(패킷/알림/라이브스트림/Sysmon/AI/지도)
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
(function () {
  /* ════════════════════ OVERVIEW 차트 ════════════════════ */
  const miniTrafficCtx = document.getElementById('mini-traffic-chart').getContext('2d');
  const miniTrafficChart = new Chart(miniTrafficCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'pps',
        data: [],
        borderColor: '#39d0d8',
        backgroundColor: 'rgba(57,208,216,.1)',
        tension: 0.4, fill: true, pointRadius: 0, borderWidth: 2,
      }],
    },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b949e', maxTicksLimit: 8, font:{size:10} }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
      },
    },
  });

  const protoCtx = document.getElementById('proto-chart').getContext('2d');
  const protoChart = new Chart(protoCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font:{size:10}, padding:6 } } },
    },
  });

  const sevCtx = document.getElementById('severity-chart').getContext('2d');
  const sevChart = new Chart(sevCtx, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      datasets: [{ data: [0, 0, 0, 0], backgroundColor: ['#f85149','#f79000','#e3b341','#58a6ff'] }],
    },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font:{size:10}, padding:6 } } },
    },
  });

  let _lastPacketChartAt = 0;

  /* ─────────── Socket: 패킷 업데이트 ─────────── */
  socket.on('packet_update', data => {
    const s = data.stats;
    document.getElementById('stat-pps').textContent = s.packets_per_sec.toLocaleString();
    document.getElementById('stat-total-packets').textContent = s.total_packets.toLocaleString();

    const now = performance.now();
    if (isPanelVisible('overview') && !document.hidden && now - _lastPacketChartAt >= 500) {
      _lastPacketChartAt = now;
      // 미니 차트 갱신
      const hist = data.traffic_history || [];
      miniTrafficChart.data.labels = hist.map(h => h.time);
      miniTrafficChart.data.datasets[0].data = hist.map(h => h.pps);
      miniTrafficChart.update('none');

      // 프로토콜 차트
      const pd = data.protocol_dist || {};
      protoChart.data.labels = Object.keys(pd);
      protoChart.data.datasets[0].data = Object.values(pd);
      protoChart.data.datasets[0].backgroundColor = Object.keys(pd).map(protoColor);
      protoChart.update('none');
    }

    // 패킷 테이블 (패킷 패널)
    if (isPanelVisible('packets')) updatePacketsTable(data.recent_packets || []);

    // 트래픽 패널 차트
    if (isPanelVisible('traffic')) updateTrafficCharts(data);
  });

  /* ─────────── Socket: 위협 알림 ─────────── */
  const _attackerCounter = {};
  const _threatTypeCounter = {};

  /* TOP 공격자 집계 상한 (docs/AUDIT.md E-3)
   *
   * 관제 화면은 며칠씩 켜둔다. 고유 공격 IP 마다 항목이 늘고 정리되지 않으면
   * 그건 진짜 누수다. 상한에 닿으면 **알림 수가 적은 IP부터** 버린다 —
   * 이 맵의 용도는 TOP 8 표시이므로 상위권을 지키는 편이 맞다(단순 LRU 로
   * 버리면 잠시 조용한 주요 공격자가 사라진다).
   *
   * 버린 IP 수는 따로 세어 KPI 가 줄어들지 않게 한다. 버려진 IP 가 다시
   * 나타나면 한 번 더 세어져 KPI 가 과대계상될 수 있으나, 상한 없이 무한히
   * 쌓이는 것보다 낫다. */
  const ATTACKER_MAP_LIMIT = 1000;
  const ATTACKER_MAP_KEEP  = 800;    // 절단 시 남길 수 (매 알림마다 자르지 않도록)
  let _attackerEvicted = 0;

  function trackAttacker(srcIp, threatType) {
    if (!srcIp) return;
    const entry = _attackerCounter[srcIp] || (_attackerCounter[srcIp] = { count: 0, type: threatType });
    entry.count++;
    entry.type = threatType;
    entry.lastSeen = Date.now();

    const keys = Object.keys(_attackerCounter);
    if (keys.length > ATTACKER_MAP_LIMIT) {
      // 알림 수 오름차순 → 같으면 오래된 것부터 버린다
      keys.sort((a, b) => (_attackerCounter[a].count - _attackerCounter[b].count)
                       || ((_attackerCounter[a].lastSeen || 0) - (_attackerCounter[b].lastSeen || 0)));
      for (const ip of keys.slice(0, keys.length - ATTACKER_MAP_KEEP)) {
        delete _attackerCounter[ip];
        _attackerEvicted++;
      }
    }
  }

  function uniqueAttackerCount() {
    return Object.keys(_attackerCounter).length + _attackerEvicted;
  }

  /* renderTopAttackers 는 전량 sort 라 매 알림마다 부르면 O(n log n) × 알림 수다.
   * 알림 폭주 시 화면이 정렬만 하다 끝나므로 300ms 로 묶는다. */
  let _topAttackersTimer = null;
  function scheduleTopAttackersRender() {
    if (_topAttackersTimer) return;
    _topAttackersTimer = setTimeout(() => {
      _topAttackersTimer = null;
      if (isPanelVisible('overview') && !document.hidden) renderTopAttackers();
    }, 300);
  }
  let _threatTypeChart = null;

  socket.on('new_alert', alert => {
    if (isPanelVisible('alerts') && !document.hidden) prependAlertRow(alert);
    if (isPanelVisible('overview') && !document.hidden) prependOverviewAlert(alert);
    updateSeverityChart(alert.severity);

    document.getElementById('stat-total-alerts').textContent =
      parseInt(document.getElementById('stat-total-alerts').textContent || 0) + 1;
    adjustOpenAlerts(+1);

    // KPI: CRITICAL / HIGH
    if (alert.severity === 'CRITICAL') incEl('kpi-critical');
    if (alert.severity === 'HIGH')     incEl('kpi-high');

    // TOP 공격자
    trackAttacker(alert.src_ip, alert.threat_type);
    document.getElementById('kpi-unique-attackers').textContent = uniqueAttackerCount();
    scheduleTopAttackersRender();

    // 위협 유형 차트
    _threatTypeCounter[alert.threat_label] = (_threatTypeCounter[alert.threat_label] || 0) + 1;
    if (isPanelVisible('overview') && !document.hidden) renderThreatTypeChart();

    // THREAT LEVEL 재계산
    if (isPanelVisible('overview') && !document.hidden) updateThreatLevel();
    if (typeof schedulePriorityReload === 'function') schedulePriorityReload();

    // 통합 라이브 스트림
    const conf = alert.confidence != null ? ` · 신뢰도 ${Math.round(alert.confidence*100)}%` : '';
    pushLive('alert', alert.severity,
      `<b style="color:${threatColor(alert.threat_type)}">${escapeHtml(alert.threat_label)}</b> ` +
      `<span class="lv-ip">${escapeHtml(alert.src_ip)}</span> → ${escapeHtml(alert.dst_ip)}${conf}` +
      demoBadge(alert.details),
      { lowConf: !!alert.details?.low_confidence });

    // 자동 AI 트리아지는 서버 SOAR에서 한 번만 수행한다.
  });

  function incEl(id) {
    const el = document.getElementById(id);
    if (el) el.textContent = parseInt(el.textContent || 0) + 1;
  }

  /* ════════════════════ 통합 라이브 이벤트 스트림 (AI 관제 센터) ════════════════════ */
  let _liveFilter = 'all';
  let _tpOnly = false;         // 정탐만 보기 (오탐 의심=저신뢰 알림 숨김)
  const _liveBuffer = [];
  const LIVE_MAX = 120;

  const LIVE_KIND_META = {
    alert:    { cls: 'k-alert',    label: '알림' },
    siem:     { cls: 'k-siem',     label: 'SIEM' },
    auth:     { cls: 'k-auth',     label: 'SSH' },
    soar:     { cls: 'k-soar',     label: '대응' },
    incident: { cls: 'k-incident', label: '인시던트' },
    ti:       { cls: 'k-ti',       label: 'IoC' },
    rep:      { cls: 'k-rep',      label: '평판' },
    edr:      { cls: 'k-edr',      label: 'EDR' },
    net:      { cls: 'k-net',      label: '네트워크' },
    sigma:    { cls: 'k-sigma',    label: 'Sigma' },
  };

  let _liveRenderTimer = null;
  function pushLive(kind, severity, html, meta) {
    const now = new Date().toTimeString().slice(0, 8);
    _liveBuffer.unshift({
      kind, severity: (severity || 'info').toLowerCase(), html, time: now,
      lowConf: !!(meta && meta.lowConf),   // 오탐 의심 알림 표시
    });
    while (_liveBuffer.length > LIVE_MAX) _liveBuffer.pop();
    // 이벤트 폭주 시 렉 방지 — 최대 ~3회/초로 렌더 배치
    if (!_liveRenderTimer && isPanelVisible('overview') && !document.hidden) {
      _liveRenderTimer = setTimeout(() => { _liveRenderTimer = null; renderLiveStream(); }, 300);
    }
  }

  function renderLiveStream() {
    const box = document.getElementById('live-stream');
    if (!box) return;
    // 화면에 안 보이면 렌더 생략(오버뷰 패널이 숨겨져 있을 때 CPU 절약)
    const ov = document.getElementById('panel-overview');
    if (ov && ov.classList.contains('d-none')) return;
    const items = _liveBuffer.filter(e =>
      (_liveFilter === 'all' || e.kind === _liveFilter) &&
      (!_tpOnly || !e.lowConf));
    if (!items.length) {
      box.innerHTML = '<div class="text-muted p-3 small text-center">이벤트 수신 대기 중…</div>';
      return;
    }
    box.innerHTML = items.slice(0, 60).map(e => {
      const meta = LIVE_KIND_META[e.kind] || { cls: '', label: e.kind };
      return `<div class="live-item">
        <div class="lv-bar b-${escapeHtml(e.severity)}"></div>
        <div class="lv-time">${escapeHtml(e.time)}</div>
        <div class="lv-kind ${meta.cls}">${meta.label}</div>
        <div class="lv-text">${e.html}</div>
      </div>`;
    }).join('');
  }

  function setLiveFilter(f, btn) {
    _liveFilter = f;
    document.querySelectorAll('.live-filter').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    renderLiveStream();
  }

  /* 정탐만 보기 토글 — 라이브 스트림 + 알림 테이블 동시 적용.
     el 이 체크박스면 checked, 버튼이면 클래스 토글로 상태 결정 후 양쪽 UI 동기화. */
  function toggleTpOnly(el) {
    if (el && el.type === 'checkbox') {
      _tpOnly = el.checked;
    } else {
      _tpOnly = !_tpOnly;
    }
    // 라이브 스트림 헤더 버튼 상태
    const liveBtn = document.querySelector('.tp-toggle');
    if (liveBtn) liveBtn.classList.toggle('active', _tpOnly);
    // 알림 패널 체크박스 상태
    const chk = document.getElementById('alert-tp-only');
    if (chk) chk.checked = _tpOnly;

    renderLiveStream();
    redrawAlertsTable();
  }

  /* 알림 테이블 '정탐만' 필터 — 오탐 의심(data-lowconf=1) 행 숨김 */
  if (window.jQuery && $.fn.dataTable) {
    $.fn.dataTable.ext.search.push((settings, data, dataIndex) => {
      if (settings.nTable.id !== 'alerts-table' || !_tpOnly) return true;
      const tr = settings.aoData[dataIndex].nTr;
      return !tr || tr.dataset.lowconf !== '1';
    });
  }

  // 파이프라인 상태 갱신
  function setPipe(id, v) {
    const el = document.getElementById(id);
    if (el && v != null) el.textContent = Number(v).toLocaleString();
  }

  /* 미처리 알림 수를 증감하며 사이드바 배지와 동기화 */
  function adjustOpenAlerts(delta) {
    const openEl = document.getElementById('stat-open-alerts');
    const sideEl = document.getElementById('sidebar-alert-count');
    const next = Math.max(0, parseInt(openEl?.textContent || 0) + delta);
    if (openEl) openEl.textContent = next;
    if (sideEl) sideEl.textContent = next;
  }
  function setOpenAlerts(n) {
    const openEl = document.getElementById('stat-open-alerts');
    const sideEl = document.getElementById('sidebar-alert-count');
    if (openEl) openEl.textContent = n;
    if (sideEl) sideEl.textContent = n;
  }

  function renderTopAttackers() {
    const el = document.getElementById('top-attackers-list');
    if (!el) return;
    const sorted = Object.entries(_attackerCounter)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 8);
    if (!sorted.length) {
      el.innerHTML = '<div class="text-muted p-2">데이터 없음</div>';
      return;
    }
    el.innerHTML = sorted.map(([ip, info], i) => `
      <div class="top-attacker-row">
        <span class="rnk">#${i+1}</span>
        <span class="ip">${escapeHtml(ip)}</span>
        <span class="ttype">${escapeHtml(info.type)}</span>
        <span class="cnt">${info.count}</span>
      </div>`).join('');
  }

  function renderThreatTypeChart() {
    const ctx = document.getElementById('threat-type-chart')?.getContext('2d');
    if (!ctx) return;
    const labels = Object.keys(_threatTypeCounter);
    const data   = Object.values(_threatTypeCounter);
    if (!_threatTypeChart) {
      _threatTypeChart = new Chart(ctx, {
        type: 'bar',
        data: { labels, datasets: [{ data, backgroundColor: '#f8514944', borderColor: '#f85149', borderWidth: 1 }] },
        options: {
          animation: false, responsive: true, maintainAspectRatio: false, indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color:'#21262d' } },
            y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color:'#21262d' } },
          },
        },
      });
    } else {
      _threatTypeChart.data.labels = labels;
      _threatTypeChart.data.datasets[0].data = data;
      _threatTypeChart.update('none');
    }
  }

  function updateThreatLevel() {
    const crit = parseInt(document.getElementById('kpi-critical').textContent || 0);
    const high = parseInt(document.getElementById('kpi-high').textContent || 0);
    const open = parseInt(document.getElementById('stat-open-alerts').textContent || 0);
    const badge = document.getElementById('threat-level-badge');
    if (!badge) return;
    badge.classList.remove('level-critical','level-high','level-medium','level-low','bg-success','bg-warning','bg-danger');
    let level = 'LOW', cls = 'level-low';
    if (crit > 0)          { level = 'CRITICAL'; cls = 'level-critical'; }
    else if (high > 0)     { level = 'HIGH';     cls = 'level-high'; }
    else if (open > 0)     { level = 'MEDIUM';   cls = 'level-medium'; }
    badge.className = `ms-3 badge ${cls}`;
    badge.textContent = `THREAT LEVEL: ${level}`;
  }

  /* ─────────── Socket: Sysmon ─────────── */
  socket.on('sysmon_update', data => {
    const s = data.stats;
    document.getElementById('stat-sysmon-events').textContent = s.total_events.toLocaleString();
    document.getElementById('sys-total').textContent = s.total_events.toLocaleString();
    document.getElementById('sys-suspicious').textContent = s.suspicious_events;
    document.getElementById('sys-critical').textContent = s.critical_events;
    if (isPanelVisible('sysmon')) updateSysmonTable(data.recent_events || []);
    if (isPanelVisible('overview')) renderOverviewSysmon(data.recent_events || []);
  });

  function renderOverviewSysmon(events) {
    const el = document.getElementById('overview-sysmon-list');
    if (!el) return;
    const latest = [...events].slice(-10).reverse();
    if (!latest.length) { el.innerHTML = '<div class="text-muted p-2">이벤트 없음</div>'; return; }
    el.innerHTML = latest.map(ev => `
      <div class="sysmon-mini-row ${ev.suspicious ? 'suspicious' : ''}">
        <span class="ts">${(ev.timestamp||'').split(' ')[1] || ''}</span>
        <span class="eid">${escapeHtml(ev.event_id)}</span>
        <span class="ename" title="${escapeHtml(ev.event_name)}">${escapeHtml(ev.event_name)}</span>
        <span>${sevBadge(ev.severity)}</span>
      </div>`).join('');
  }

  socket.on('sysmon_alert', event => {
    // 의심 Sysmon 이벤트는 빨간 행으로 강조
    if (isPanelVisible('sysmon') && !document.hidden) updateSysmonTable([event], true);
  });

  /* ─────────── Socket: AI 분석 (패널 제거 — 네비 배지만 갱신) ─────────── */
  socket.on('ai_analysis', () => {
    const el = document.getElementById('stat-ai-analyses');
    if (el) el.textContent = parseInt(el.textContent || 0) + 1;
    const badge = document.getElementById('ai-status-badge');
    if (badge) {
      badge.textContent = 'AI 분석 완료';
      badge.className = 'badge bg-success';
      setTimeout(() => {
        badge.textContent = 'AI 대기중';
        badge.className = 'badge bg-secondary';
      }, 4000);
    }
  });

  /* ─────────── Socket: 지도 공격 ─────────── */
  socket.on('map_attack', entry => {
    if (!isPanelVisible('overview') || document.hidden) return;
    animateAttack(entry);
    prependAttackLog(entry);
    updateCountryChart(entry.src_country);
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    _threatTypeCounter, adjustOpenAlerts, incEl, pushLive, renderLiveStream,
    renderThreatTypeChart, renderTopAttackers, setLiveFilter, setOpenAlerts, setPipe,
    sevChart, toggleTpOnly, trackAttacker, uniqueAttackerCount, updateThreatLevel,
  });
})();
