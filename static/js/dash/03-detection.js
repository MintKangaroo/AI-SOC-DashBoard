/* dashboard/03-detection.js — 알림 패널·패킷/트래픽/Sysmon 테이블·AI 분석·3D 지도
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
/* ════════════════════ 알림 패널 ════════════════════ */
let alertsDataTable = null;

function loadAlerts() {
  fetch('/api/alerts?limit=200')
    .then(r => r.json())
    .then(d => {
      const tbody = document.getElementById('alerts-tbody');
      if (alertsDataTable) {
        alertsDataTable.clear();
        d.alerts.forEach(a => prependAlertRow(a, false, false));
        alertsDataTable.draw(false);
      } else {
        tbody.innerHTML = '';
        d.alerts.forEach(a => prependAlertRow(a, false, false));
        alertsDataTable = $('#alerts-table').DataTable({
          order: [[0, 'desc']],
          pageLength: 20,
          language: { url: '' },
        });
      }
    });
}

/* 데모 모드에서 합성된 이벤트임을 알리는 회색 배지 */
function demoBadge(details) {
  return details && details.demo
    ? ' <span class="badge demo-badge" title="데모 모드에서 생성된 합성 이벤트 — 실제 침해 아님">데모</span>'
    : '';
}

function confBadge(alert) {
  const c = alert.confidence ?? alert.details?.confidence;
  if (c == null) return '';
  if (alert.details?.low_confidence) {
    return ` <span class="badge bg-orange" style="font-size:9px" title="신뢰도 ${Math.round(c*100)}% — 임계값 미만">오탐 의심</span>`;
  }
  const cls = c >= 0.75 ? 'bg-success' : 'bg-secondary';
  return ` <span class="badge ${cls}" style="font-size:9px" title="정탐 신뢰도">${Math.round(c*100)}%</span>`;
}

/* 중복 병합 횟수 뱃지 — 같은 핑거프린트가 윈도우 내에 몇 번 재발했는지 */
function dedupBadge(alert) {
  const n = alert.details?.dedup?.count;
  if (!n || n < 2) return '';
  const storm = alert.details?.dedup?.storm;
  const cls = storm ? 'bg-danger' : 'bg-info text-dark';
  const title = `동일 이벤트 ${n}건 병합 · 최근 ${alert.details.dedup.last_seen || '-'}`;
  return ` <span class="badge ${cls} dedup-count" style="font-size:9px" title="${escapeHtml(title)}">×${n}</span>`;
}

function verdictBadge(alert) {
  const map = {
    UNREVIEWED: ['bg-secondary', '미판정'], INVESTIGATING: ['bg-info text-dark', '조사 중'],
    TRUE_POSITIVE: ['bg-danger', '정탐 확정'], FALSE_POSITIVE: ['bg-success', '오탐 확정'],
  };
  const [cls, label] = map[alert.verdict] || map.UNREVIEWED;
  const title = [alert.verdict_actor, alert.verdict_at, alert.verdict_reason].filter(Boolean).join(' · ');
  return `<span class="badge ${cls}" title="${escapeHtml(title)}">${label}</span>`;
}

function prependAlertRow(alert, prepend = true, draw = true) {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  const statusColors = { OPEN: 'danger', ACK: 'warning', CLOSED: 'secondary' };
  const statusLabels = { OPEN: '미처리', ACK: '확인됨', CLOSED: '종료' };
  const row = document.createElement('tr');
  row.id = `alert-row-${alert.id}`;
  row.dataset.lowconf = alert.details?.low_confidence ? '1' : '0';   // 정탐만 필터용
  row.innerHTML = `
    <td>${escapeHtml(alert.timestamp)}</td>
    <td>${sevBadge(alert.severity)}</td>
    <td><span style="color:${threatColor(alert.threat_type)}">${escapeHtml(alert.threat_label)}</span>${dedupBadge(alert)}${confBadge(alert)}${demoBadge(alert.details)}</td>
    <td>${alert.origin === 'demo' ? '<span class="badge demo-badge">데모</span>' : alert.origin === 'real' ? '<span class="badge bg-primary">실데이터</span>' : '<span class="badge bg-secondary">기존</span>'}</td>
    <td class="font-monospace">${escapeHtml(alert.src_ip)}</td>
    <td class="font-monospace">${escapeHtml(alert.dst_ip)}</td>
    <td>${escapeHtml(alert.description)}</td>
    <td><span class="badge bg-${statusColors[alert.status]}">${statusLabels[alert.status]}</span></td>
    <td>${verdictBadge(alert)}</td>
    <td>
      <button class="btn btn-xs btn-outline-info me-1" onclick="analyzeAlertAI(${alert.id})">
        <i class="fa fa-robot"></i>
      </button>
      <button class="btn btn-xs btn-outline-warning me-1" onclick="updateAlertStatus(${alert.id},'ACK')">확인</button>
      <button class="btn btn-xs btn-outline-danger me-1" onclick="setAlertVerdict(${alert.id},'TRUE_POSITIVE')">정탐</button>
      <button class="btn btn-xs btn-outline-success me-1" onclick="setAlertVerdict(${alert.id},'FALSE_POSITIVE')">오탐</button>
      <button class="btn btn-xs btn-outline-secondary" onclick="updateAlertStatus(${alert.id},'CLOSED')">종료</button>
    </td>`;
  // 실시간 이벤트가 장시간 누적되어 DOM/DataTables가 느려지는 것을 방지한다.
  // DataTables가 관리 중이면 API를 통해, 초기화 전이면 DOM에서 직접 제거한다.
  const maxRows = 200;
  if (alertsDataTable) {
    alertsDataTable.row.add(row);
    while (alertsDataTable.rows().count() > maxRows) {
      alertsDataTable.row(':last').remove();
    }
    if (draw) alertsDataTable.draw(false);
  } else {
    if (prepend && tbody.firstChild) tbody.insertBefore(row, tbody.firstChild);
    else tbody.appendChild(row);
    while (tbody.children.length > maxRows) tbody.removeChild(tbody.lastChild);
  }
}

/* 중복 병합 알림: 새 행을 만들지 않고 기존 행의 ×N 뱃지만 갱신한다 */
socket.on('alert_dedup', d => {
  const row = document.getElementById(`alert-row-${d.alert_id}`);
  if (row) {
    const cell = row.querySelector('td:nth-child(3)');
    if (cell) {
      const existing = cell.querySelector('.dedup-count');
      const title = `동일 이벤트 ${d.count}건 병합 · 최근 ${d.last_seen || '-'}`;
      if (existing) {
        existing.textContent = `×${d.count}`;
        existing.title = title;
      } else {
        const span = document.createElement('span');
        span.className = 'badge bg-info text-dark dedup-count';
        span.style.fontSize = '9px';
        span.textContent = `×${d.count}`;
        span.title = title;
        cell.appendChild(document.createTextNode(' '));
        cell.appendChild(span);
      }
    }
  }
  const badge = document.getElementById('dedup-merged-count');
  if (badge) badge.textContent = (parseInt(badge.textContent.replace(/,/g, '')) || 0) + 1;
});

/* ── 억제됨 탭 ── */
function loadSuppressed(page = 1) {
  const kind = document.getElementById('supp-kind-filter')?.value || '';
  const params = new URLSearchParams({ page, limit: 50 });
  if (kind) params.set('kind', kind);
  fetch('/api/dedup/suppressed?' + params)
    .then(r => r.json())
    .then(renderSuppressed)
    .catch(() => {});
  fetch('/api/dedup/status')
    .then(r => r.json())
    .then(d => {
      const s = d.stats || {};
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('dedup-seen', (s.seen || 0).toLocaleString());
      set('dedup-merged-count', (s.deduplicated || 0).toLocaleString());
      set('dedup-suppressed-count', (s.suppressed || 0).toLocaleString());
      set('dedup-reduction', (s.reduction_rate ?? 0) + '%');
      set('dedup-window', (s.window_seconds ?? '-') + '초');
      set('dedup-storms', (s.storms || 0).toLocaleString());
    })
    .catch(() => {});
}

function renderSuppressed(d) {
  const tbody = document.getElementById('suppressed-tbody');
  if (!tbody) return;
  const rows = d.events || [];
  const kindMeta = {
    duplicate: ['bg-info text-dark', '중복 병합'],
    suppressed: ['bg-warning text-dark', '규칙 억제'],
    storm: ['bg-danger', '스톰'],
  };
  tbody.innerHTML = rows.length
    ? rows.map(e => {
        const [cls, label] = kindMeta[e.kind] || ['bg-secondary', e.kind];
        return `<tr style="color:#e6edf3">
          <td class="small font-monospace text-nowrap">${escapeHtml(e.ts)}</td>
          <td><span class="badge ${cls}" style="font-size:9px">${label}</span></td>
          <td>${sevBadge(e.severity)}</td>
          <td class="small">${escapeHtml(e.threat_type || '')}</td>
          <td class="small font-monospace">${escapeHtml(e.src_ip || '-')}</td>
          <td class="small">${escapeHtml(e.description || '')}</td>
          <td class="small text-muted">${escapeHtml(e.reason || '')}</td>
          <td class="small font-monospace">${e.parent_alert ? '#' + e.parent_alert : '-'}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="8" class="text-muted text-center p-3">억제된 이벤트 없음</td></tr>';

  const summary = document.getElementById('supp-summary');
  if (summary) {
    summary.textContent = `총 ${(d.total || 0).toLocaleString()}건 중 ${rows.length}건 표시 (${d.page}/${d.pages} 페이지)`;
  }
}

function updateAlertStatus(id, status) {
  fetch(`/api/alerts/${id}/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  }).then(() => {
    const row = document.getElementById(`alert-row-${id}`);
    if (row) {
      const badges = { OPEN:'danger', ACK:'warning', CLOSED:'secondary' };
      const labels = { OPEN:'미처리', ACK:'확인됨', CLOSED:'종료' };
      row.querySelector('td:nth-child(8)').innerHTML =
        `<span class="badge bg-${badges[status]}">${labels[status]}</span>`;
    }
    // ACK / CLOSED 모두 미처리 수에서 제외
    if (status === 'ACK' || status === 'CLOSED') {
      adjustOpenAlerts(-1);
    }
    if (status === 'CLOSED') {
      incEl('kpi-blocked');
    }
  });
}

function setAlertVerdict(id, verdict) {
  const label = verdict === 'TRUE_POSITIVE' ? '정탐' : '오탐';
  const reason = prompt(`${label} 확정 근거를 입력하세요 (필수)`);
  if (reason == null) return;
  fetch(`/api/alerts/${id}/verdict`, {
    method: 'PUT', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({verdict, reason}),
  }).then(async r => ({ok:r.ok, body:await r.json()})).then(({ok, body}) => {
    if (!ok) { alert(body.error || '판정 저장 실패'); return; }
    loadAlerts();
  });
}

/* 개요 카드 클릭 → 알림 패널로 이동하며 필터 적용 */
function filterAlerts(severity) {
  showPanel('alerts');
  // DataTables 초기화 후 필터 적용 (비동기)
  setTimeout(() => {
    if (alertsDataTable) {
      alertsDataTable.column(1).search(severity, false, false).draw();
    }
  }, 150);
}

function filterAlertsByStatus(statusLabel) {
  showPanel('alerts');
  const mapKo = { CLOSED: '종료', ACK: '확인됨', OPEN: '미처리' };
  const q = mapKo[statusLabel] || statusLabel;
  setTimeout(() => {
    if (alertsDataTable) {
      alertsDataTable.column(7).search(q, false, false).draw();
    }
  }, 150);
}

function prependOverviewAlert(alert) {
  const list = document.getElementById('recent-alerts-list');
  if (!list) return;
  const item = document.createElement('div');
  item.className = `alert-item ${alert.severity}`;
  item.innerHTML = `
    <div>${sevBadge(alert.severity)}</div>
    <div class="flex-fill">
      <span style="color:${threatColor(alert.threat_type)};font-weight:600">${escapeHtml(alert.threat_label)}</span>${demoBadge(alert.details)}
      <span class="text-muted ms-2">${escapeHtml(alert.src_ip)} → ${escapeHtml(alert.dst_ip)}</span>
      <div class="text-muted" style="font-size:11px">${escapeHtml(alert.description)}</div>
    </div>
    <div class="text-muted" style="font-size:10px;white-space:nowrap">${alert.timestamp.split(' ')[1]||alert.timestamp}</div>`;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 8) list.removeChild(list.lastChild);
}

function updateSeverityChart(sev) {
  const idx = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[sev];
  if (idx !== undefined) {
    sevChart.data.datasets[0].data[idx]++;
    if (isPanelVisible('overview') && !document.hidden) sevChart.update('none');
  }
}

/* ════════════════════ 패킷 테이블 ════════════════════ */
let packetsInit = false;
let packetsTable = null;

function initPacketsTable() {
  if (!packetsInit) {
    packetsTable = $('#packets-table').DataTable({
      order: [[0, 'desc']],
      pageLength: 30,
      scrollY: '520px',
      scrollCollapse: true,
    });
    packetsInit = true;
  }
}

function updatePacketsTable(packets) {
  const tbody = document.getElementById('packets-tbody');
  if (!tbody || !packetsInit) return;
  packets.slice(-10).forEach(p => {
    const row = document.createElement('tr');
    row.style.color = '#e6edf3';
    row.innerHTML = `
      <td style="color:#e6edf3">${escapeHtml(p.time)}</td>
      <td style="color:#e6edf3">${escapeHtml(p.src_ip)}</td>
      <td style="color:#e6edf3">${escapeHtml(p.dst_ip)}</td>
      <td style="color:#e6edf3">${p.src_port || '-'}</td>
      <td style="color:#e6edf3">${p.dst_port || '-'}</td>
      <td><span style="color:${protoColor(p.protocol)};font-weight:600">${escapeHtml(p.protocol)}</span></td>
      <td style="color:#e6edf3">${p.length}</td>
      <td style="color:#e6edf3">${escapeHtml(p.info)}</td>`;
    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
  });
}

/* ════════════════════ 트래픽 차트 ════════════════════ */
let trafficInited = false;
let trafficPpsChart, trafficBpsChart, topTalkersChart, protoDist2Chart;

function initTrafficCharts() {
  if (trafficInited) return;
  trafficInited = true;

  const commonOpts = (label, color) => ({
    type: 'line',
    data: { labels: [], datasets: [{ label, data: [], borderColor: color,
      backgroundColor: color + '22', tension: 0.4, fill: true, pointRadius: 0, borderWidth: 2 }] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b949e', maxTicksLimit: 10, font:{size:10} }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
      },
    },
  });

  trafficPpsChart = new Chart(
    document.getElementById('traffic-pps-chart').getContext('2d'),
    commonOpts('패킷/초', '#39d0d8')
  );
  trafficBpsChart = new Chart(
    document.getElementById('traffic-bps-chart').getContext('2d'),
    commonOpts('바이트/초', '#9d79f2')
  );
  topTalkersChart = new Chart(
    document.getElementById('top-talkers-chart').getContext('2d'), {
      type: 'bar',
      data: { labels: [], datasets: [{ label: '패킷 수', data: [], backgroundColor: '#39d0d822', borderColor: '#39d0d8', borderWidth: 1 }] },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font:{size:10}, maxTicksLimit: 10 }, grid: { color: '#21262d' } },
        },
      },
    }
  );
  protoDist2Chart = new Chart(
    document.getElementById('proto-dist-chart').getContext('2d'), {
      type: 'bar',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
        },
      },
    }
  );
}

function updateTrafficCharts(data) {
  if (!trafficInited) return;
  const hist = data.traffic_history || [];
  trafficPpsChart.data.labels = hist.map(h => h.time);
  trafficPpsChart.data.datasets[0].data = hist.map(h => h.pps);
  trafficPpsChart.update('none');

  trafficBpsChart.data.labels = hist.map(h => h.time);
  trafficBpsChart.data.datasets[0].data = hist.map(h => h.bps);
  trafficBpsChart.update('none');

  const tt = data.top_talkers || [];
  topTalkersChart.data.labels = tt.map(t => t[0]);
  topTalkersChart.data.datasets[0].data = tt.map(t => t[1]);
  topTalkersChart.update('none');

  const pd = data.protocol_dist || {};
  protoDist2Chart.data.labels = Object.keys(pd);
  protoDist2Chart.data.datasets[0].data = Object.values(pd);
  protoDist2Chart.data.datasets[0].backgroundColor = Object.keys(pd).map(protoColor);
  protoDist2Chart.update('none');
}

/* ════════════════════ SYSMON 테이블 ════════════════════ */
let sysmonInit = false;
let sysmonDT = null;
const _seenSysmonEvents = new Set();
const _seenSysmonOrder = [];

function initSysmonTable() {
  if (!sysmonInit) {
    sysmonDT = $('#sysmon-table').DataTable({
      order: [[0, 'desc']],
      pageLength: 25,
      scrollY: '420px',
      scrollCollapse: true,
    });
    sysmonInit = true;
  }
}

function updateSysmonTable(events, highlight = false) {
  const tbody = document.getElementById('sysmon-tbody');
  if (!tbody) return;
  events.forEach(ev => {
    // 서버는 최근 20건을 반복 전송하므로 동일 이벤트를 다시 붙이지 않는다.
    const key = [ev.timestamp, ev.event_id, ev.process || '', ev.message || ''].join('|');
    if (_seenSysmonEvents.has(key)) return;
    _seenSysmonEvents.add(key);
    _seenSysmonOrder.push(key);
    while (_seenSysmonOrder.length > 500) {
      _seenSysmonEvents.delete(_seenSysmonOrder.shift());
    }
    const row = document.createElement('tr');
    row.style.color = '#e6edf3';
    if (ev.suspicious || highlight) row.style.background = 'rgba(248,81,73,.08)';
    row.innerHTML = `
      <td style="color:#e6edf3">${escapeHtml(ev.timestamp)}</td>
      <td style="color:#e6edf3">${escapeHtml(ev.event_id)}</td>
      <td style="color:#e6edf3">${escapeHtml(ev.event_name)}</td>
      <td>${sevBadge(ev.severity)}</td>
      <td class="font-monospace text-truncate" style="max-width:120px;color:#e6edf3" title="${escapeHtml(ev.process||'')}">${escapeHtml(ev.process||'-')}</td>
      <td class="text-truncate" style="max-width:240px;color:#e6edf3" title="${escapeHtml(ev.message)}">${escapeHtml(ev.message)}</td>
      <td>${ev.suspicious ? '<span class="badge bg-danger">의심</span>' : ''}</td>`;
    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
  });
}

/* ════════════════════ AI 분석 (패널은 제거됨 — 알림 테이블에서만 호출) ════════════════════ */
function analyzeAlertAI(alertId) {
  fetch(`/api/ai/analyze/alert/${alertId}`, { method: 'POST' })
    .then(r => r.json())
    .then(d => {
      const r = d.result || {};
      const msg = r.summary || r.raw_response || JSON.stringify(r, null, 2);
      alert(`[AI 분석 결과]\n\n${msg}`);
    });
}

function analyzeTrafficAI() {
  fetch('/api/ai/analyze/traffic', { method: 'POST' })
    .then(r => r.json())
    .then(d => {
      const r = d.result || {};
      const msg = r.summary || r.raw_response || JSON.stringify(r, null, 2);
      alert(`[AI 트래픽 분석]\n\n${msg}`);
    });
}

/* ════════════════════ 공격 지도 (3D 지구본) ════════════════════ */
let globe = null;
let globeInited = false;
const countryCounter = {};
let countryChart = null;

// Globe.gl 데이터 버퍼
let _globeArcs = [];
let _globeRings = [];
let _globePoints = [];

const DEFENDER = { lat: 37.5665, lng: 126.9780, label: 'Seoul (방어 서버)' };

function initMap() {
  if (globeInited) return;
  const el = document.getElementById('attack-globe');
  if (!el || typeof Globe === 'undefined') return;
  globeInited = true;

  globe = Globe()(el)
    .backgroundColor('rgba(0,0,0,0)')       // 패널 그라디언트가 우주 배경으로 비침
    .showGlobe(true)
    .showGraticules(false)
    .atmosphereColor('#39d0d8')
    .atmosphereAltitude(0.18)
    .showAtmosphere(true)
    // 대륙을 점(hex dot)으로 그린 사이버 점묘 지구본
    .hexPolygonsData([])
    .hexPolygonResolution(3)
    .hexPolygonMargin(0.28)
    .hexPolygonUseDots(true)
    .hexPolygonAltitude(0.003)
    .hexPolygonColor(() => 'rgba(92,173,208,0.55)')
    // Arcs (공격 궤적)
    .arcsData(_globeArcs)
    .arcStartLat(d => d.startLat).arcStartLng(d => d.startLng)
    .arcEndLat(d => d.endLat).arcEndLng(d => d.endLng)
    .arcColor(d => d.color)
    .arcStroke(0.4)
    .arcDashLength(0.35).arcDashGap(1.2)
    .arcDashInitialGap(() => 1)
    .arcDashAnimateTime(1800)
    .arcAltitudeAutoScale(0.45)
    // Rings (임팩트/레이더 펄스)
    .ringsData(_globeRings)
    .ringColor(d => t => `rgba(${d.rgb},${1 - t})`)
    .ringMaxRadius(d => d.maxR || 5)
    .ringPropagationSpeed(d => d.speed || 3)
    .ringRepeatPeriod(d => d.repeat || 800)
    .ringAltitude(0.008)
    // Points (공격자/방어자 마커)
    .pointsData(_globePoints)
    .pointLat(d => d.lat).pointLng(d => d.lng)
    .pointColor(d => d.color)
    .pointAltitude(d => d.alt || 0.01)
    .pointRadius(d => d.radius || 0.3)
    .pointLabel(d => d.label || '');

  // 크기 맞추기
  const resize = () => {
    globe.width(el.clientWidth);
    globe.height(el.clientHeight);
  };
  resize();
  window.addEventListener('resize', resize);

  // 짙은 남색 바다 구체 (사진 텍스처 대신 단색 머티리얼)
  if (typeof THREE !== 'undefined') {
    const gm = globe.globeMaterial();
    gm.color = new THREE.Color(0x081726);
    gm.emissive = new THREE.Color(0x0a2036);
    gm.emissiveIntensity = 0.35;
    gm.shininess = 0.3;
  }

  // 국가 폴리곤을 점 패턴으로 로드 (로컬 번들 GeoJSON)
  fetch('/static/data/countries-110m.geojson')
    .then(r => r.json())
    .then(geo => { if (globe && geo && geo.features) globe.hexPolygonsData(geo.features); })
    .catch(() => { /* 실패 시 바다 구체만 표시 */ });

  // 한국 중심 고정 (자동 회전 OFF)
  const controls = globe.controls();
  controls.autoRotate = false;
  controls.enableZoom = true;
  globe.pointOfView({ lat: DEFENDER.lat, lng: DEFENDER.lng, altitude: 2.2 }, 0);

  // 방어자(서울) 마커 + 상시 레이더 펄스 링
  _globePoints.push({
    lat: DEFENDER.lat, lng: DEFENDER.lng, color: '#39d0d8',
    radius: 0.55, alt: 0.012, label: `<b style="color:#39d0d8">🛡 ${DEFENDER.label}</b>`
  });
  _globeRings.push({
    lat: DEFENDER.lat, lng: DEFENDER.lng,
    rgb: '57,208,216', maxR: 4, speed: 1.8, repeat: 1400,
  });
  globe.pointsData([..._globePoints]).ringsData([..._globeRings]);
}

function animateAttack(entry) {
  if (!globeInited || !globe) return;

  const sevColors = {
    CRITICAL: '#ff2d5e', HIGH: '#ff7b00', MEDIUM: '#ffd23f', LOW: '#00e1ff'
  };
  const sevRgb = {
    CRITICAL: '255,45,94', HIGH: '255,123,0', MEDIUM: '255,210,63', LOW: '0,225,255'
  };
  const color = sevColors[entry.severity] || '#8b949e';
  const rgb   = sevRgb[entry.severity]   || '139,148,158';

  // Arc (미사일 궤적)
  const arc = {
    startLat: entry.src_lat, startLng: entry.src_lng,
    endLat:   entry.dst_lat || DEFENDER.lat,
    endLng:   entry.dst_lng || DEFENDER.lng,
    color:    [color + '00', color, color + '00'],  // 그라디언트
  };
  _globeArcs.push(arc);
  if (_globeArcs.length > 40) _globeArcs.shift();
  globe.arcsData([..._globeArcs]);

  // 출발지 마커 (공격자)
  const atk = {
    lat: entry.src_lat, lng: entry.src_lng, color,
    radius: 0.35, alt: 0.008,
    label: `<b style="color:${color}">⚠ ${escapeHtml(entry.src_country || '')}</b> ${escapeHtml(entry.src_city || '')}<br/>
            IP: <span style="font-family:monospace">${escapeHtml(entry.ip)}</span><br/>
            유형: <b>${escapeHtml(entry.threat_type)}</b><br/>등급: ${escapeHtml(entry.severity)}`,
  };
  _globePoints.push(atk);
  if (_globePoints.length > 80) _globePoints.splice(1, 1);  // 0번은 방어자
  globe.pointsData([..._globePoints]);

  // 임팩트 링 (도착 후 트리거)
  setTimeout(() => {
    const impact = {
      lat: arc.endLat, lng: arc.endLng, rgb,
      maxR: 6, speed: 5, repeat: 0,
    };
    _globeRings.push(impact);
    globe.ringsData([..._globeRings]);
    setTimeout(() => {
      const i = _globeRings.indexOf(impact);
      if (i > -1) _globeRings.splice(i, 1);
      globe.ringsData([..._globeRings]);
    }, 2500);
  }, 1600);

  // 출발지 마커는 8초 후 제거
  setTimeout(() => {
    const i = _globePoints.indexOf(atk);
    if (i > -1) _globePoints.splice(i, 1);
    globe.pointsData([..._globePoints]);
  }, 8000);
}

function prependAttackLog(entry) {
  const list = document.getElementById('attack-log');
  if (!list) return;
  const item = document.createElement('div');
  item.className = 'attack-log-item';
  item.innerHTML = `
    <span class="country">${escapeHtml(entry.src_country)} &rarr; Seoul</span>
    <span class="meta">${escapeHtml(entry.threat_type)} | ${escapeHtml(entry.ip)}</span>
    <span class="meta">${escapeHtml(entry.timestamp)} | ${sevBadge(entry.severity)}</span>`;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 50) list.removeChild(list.lastChild);
}

function updateCountryChart(country) {
  countryCounter[country] = (countryCounter[country] || 0) + 1;
  const sorted = Object.entries(countryCounter).sort((a, b) => b[1] - a[1]).slice(0, 10);

  if (!countryChart) {
    const ctx = document.getElementById('country-chart')?.getContext('2d');
    if (!ctx) return;
    countryChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: sorted.map(s => s[0]),
        datasets: [{ data: sorted.map(s => s[1]), backgroundColor: '#f8514944', borderColor: '#f85149', borderWidth: 1 }],
      },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
        },
      },
    });
  } else {
    countryChart.data.labels = sorted.map(s => s[0]);
    countryChart.data.datasets[0].data = sorted.map(s => s[1]);
    countryChart.update('none');
  }
}
