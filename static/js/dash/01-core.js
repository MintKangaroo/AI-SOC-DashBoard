/* dashboard/01-core.js — 유틸·사이드바·패널전환·내 정보·시간
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
(function () {
  /* ══════════════════════════════════════════
     SOC Dashboard — Main JS
  ══════════════════════════════════════════ */

  /* DataTables 공통 설정.

     언어: 대시보드는 전부 한국어인데 표 컨트롤만 "Show / entries / Search:" 였다.
     한 곳에서 기본값으로 정한다.

     ※ 알림 표에는 `language: { url: '' }` 가 들어가 있었다. DataTables 는 이걸
       "언어 파일을 이 URL 에서 받아라" 로 읽어 빈 URL(=현재 페이지)을 JSON 으로
       파싱하려다 실패했고, 그 바람에 길이 셀렉트의 `_MENU_` 가 치환되지 않아
       **옵션 없는 빈 상자**로 떴다. 색 문제로 보였지만 설정이 깨진 것이었다.

     컨트롤에 폼 유틸(.bg-dark 등)을 붙이는 이유: 이 저장소의 다른 폼 요소가
     모두 그 관례를 쓰는데 DT 가 만드는 컨트롤에는 없어서 혼자 달라 보였다. */
  if (window.jQuery && jQuery.fn.dataTable) {
    jQuery.extend(true, jQuery.fn.dataTable.defaults, {
      /* 기본 길이 메뉴는 [10,25,50,100] 인데 알림 표는 pageLength: 20 을 쓴다.
         현재 값과 일치하는 option 이 없으면 셀렉트는 **아무것도 선택되지 않은
         빈 상자**로 뜬다 — 흰 상자로 보였던 것의 정체가 이것이다. 20 을 넣고,
         "전체" 도 함께 준다(관제에서 한 화면에 다 보고 싶을 때가 있다). */
      lengthMenu: [[10, 20, 50, 100, -1], ['10', '20', '50', '100', '전체']],
      language: {
        lengthMenu: '_MENU_ 개씩 보기',
        search: '검색:',
        searchPlaceholder: '표 안에서 찾기',
        info: '_TOTAL_건 중 _START_–_END_',
        infoEmpty: '표시할 항목 없음',
        infoFiltered: '(전체 _MAX_건에서 필터)',
        zeroRecords: '조건에 맞는 항목이 없습니다',
        emptyTable: '아직 데이터가 없습니다',
        paginate: { first: '처음', last: '마지막', next: '다음', previous: '이전' },
      },
    });
    jQuery(document).on('init.dt', function (e, settings) {
      const api = new jQuery.fn.dataTable.Api(settings);
      jQuery(api.table().container())
        .find('select, input[type="search"], input[type="text"]')
        .addClass('bg-dark text-white border-secondary');
    });
  }

  /* 세션 만료 감지: /api 응답이 401이면 로그인 페이지로 이동 */
  (function () {
    const _fetch = window.fetch;
    window.fetch = function (...args) {
      return _fetch.apply(this, args).then(res => {
        if (res.status === 401 && String(args[0] || '').includes('/api/')) {
          window.location.href = '/login';
        }
        return res;
      });
    };
  })();

  /* HTML 이스케이프 — 여러 파일이 공유하는 공용 헬퍼다.
     원래 04-ml-mitre.js 에 있었으나 01 부터 쓰이므로 여기로 옮겼다. */
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g,
      c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  const socket = io();

  /* ════════════════════ API 오류 표면화 ════════════════════
     서버는 이제 어떤 실패에도 /api/ 에 JSON 을 돌려준다(docs/AUDIT.md A-3).
     문제는 프론트다 — 39곳이 `.catch(() => {})` 로 실패를 조용히 삼켜
     패널이 빈 채로 남고 사용자는 이유를 알 수 없었다.

     호출부 39곳을 고치는 대신 fetch 를 한 겹 감싼다. 응답 본문은 건드리지
     않으므로 기존 코드는 그대로 동작하고, 실패했을 때만 배너가 뜬다.
     error_id 를 함께 보여줘 서버 로그와 대조할 수 있게 한다. */
  (function wrapFetchForErrorSurfacing() {
    const original = window.fetch;
    if (!original || window.__socFetchWrapped) return;
    window.__socFetchWrapped = true;

    window.fetch = function (input, init) {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      return original.call(this, input, init).then(response => {
        if (url.includes('/api/') && !response.ok) {
          // 본문을 소비하면 호출부가 못 읽으므로 복제본에서만 읽는다
          response.clone().json()
            .then(body => showApiError(url, response.status, body))
            .catch(() => showApiError(url, response.status, null));
        }
        return response;
      }).catch(err => {
        if (url.includes('/api/')) showApiError(url, 0, null);
        throw err;
      });
    };
  })();

  function showApiError(url, status, body) {
    // 인증 만료는 로그인 페이지로 보내는 것이 자연스럽다 — 배너 대신 이동
    if (body && body.auth_required) {
      window.location.href = '/login';
      return;
    }
    const path = String(url).replace(/^https?:\/\/[^/]+/, '');
    const parts = [];
    if (status) parts.push(`HTTP ${status}`);
    if (body && body.error) parts.push(body.error);
    if (body && body.error_id) parts.push(`오류 ID ${body.error_id}`);
    if (!parts.length) parts.push('요청 실패');
    renderApiErrorBanner(`${path} — ${parts.join(' · ')}`);
  }

  /* 같은 메시지가 반복될 때 배너를 쌓지 않고 횟수만 올린다 */
  const _apiErrorSeen = new Map();

  function renderApiErrorBanner(message) {
    let box = document.getElementById('api-error-stack');
    if (!box) {
      box = document.createElement('div');
      box.id = 'api-error-stack';
      box.setAttribute('style',
        'position:fixed;right:16px;bottom:16px;z-index:2000;max-width:460px;' +
        'display:flex;flex-direction:column;gap:6px');
      document.body.appendChild(box);
    }
    const existing = _apiErrorSeen.get(message);
    if (existing && document.body.contains(existing.el)) {
      existing.count += 1;
      const badge = existing.el.querySelector('.api-err-count');
      if (badge) badge.textContent = `×${existing.count}`;
      return;
    }

    const item = document.createElement('div');
    item.className = 'api-error-toast';
    item.setAttribute('style',
      'background:#2d1416;border:1px solid #f85149;' +
      'color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:11.5px;' +
      'display:flex;gap:8px;align-items:flex-start;box-shadow:0 2px 8px rgba(0,0,0,.4)');
    item.innerHTML =
      '<i class="fa fa-triangle-exclamation" style="color:#f85149;margin-top:2px"></i>' +
      `<span style="flex:1;word-break:break-all">${escapeHtml(message)}</span>` +
      '<span class="api-err-count" style="color:#8b949e">×1</span>' +
      '<button type="button" style="background:none;border:none;color:#8b949e;' +
      'cursor:pointer;padding:0 2px;line-height:1">&times;</button>';
    item.querySelector('button').onclick = () => {
      item.remove();
      _apiErrorSeen.delete(message);
    };
    box.appendChild(item);
    _apiErrorSeen.set(message, { el: item, count: 1 });

    setTimeout(() => {
      item.remove();
      _apiErrorSeen.delete(message);
    }, 15000);
  }

  // 소켓 인증 실패(미로그인) 시 로그인 페이지로
  socket.on('connect_error', () => { window.location.href = '/login'; });

  /* ─────────────────── 유틸 ─────────────────── */
  function fmtBytes(b) {
    if (b < 1024)       return b + ' B';
    if (b < 1048576)    return (b/1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
    return (b/1073741824).toFixed(2) + ' GB';
  }

  function sevBadge(sev) {
    return `<span class="badge sev-${sev}">${sev}</span>`;
  }

  function protoColor(p) {
    const m = { TCP:'#39d0d8', UDP:'#9d79f2', ICMP:'#e3b341', ARP:'#3fb950', OTHER:'#8b949e' };
    return m[p] || '#8b949e';
  }

  function threatColor(t) {
    const m = { DDOS:'#f85149', PORT_SCAN:'#f79000', BRUTE_FORCE:'#e3b341',
                 MALWARE_BEACON:'#f85149', DATA_EXFIL:'#f79000',
                 ARP_SPOOFING:'#9d79f2', DNS_TUNNELING:'#58a6ff', ANOMALY:'#8b949e' };
    return m[t] || '#8b949e';
  }

  /* 실시간 이벤트는 모든 패널에 도착한다. 숨겨진 패널·백그라운드 탭의
     무거운 차트/테이블 렌더를 생략해 장시간 실행 시 브라우저 부하를 줄인다. */
  function isPanelVisible(name) {
    if (document.hidden) return false;
    const panel = document.getElementById('panel-' + name);
    return !!panel && !panel.classList.contains('d-none');
  }

  /* ─────────────────── 모바일 사이드바 드로어 ─────────────────── */
  function toggleSidebar() {
    const sb = document.getElementById('sidebar');
    const bd = document.getElementById('sidebar-backdrop');
    const open = sb.classList.toggle('open');
    if (bd) bd.classList.toggle('show', open);
  }
  function closeSidebar() {
    document.getElementById('sidebar')?.classList.remove('open');
    document.getElementById('sidebar-backdrop')?.classList.remove('show');
  }

  /* ─────────────────── 사이드바 접이식 그룹 ─────────────────── */
  function toggleGroup(name) {
    const body = document.getElementById('sgroup-' + name);
    const head = document.getElementById('sgroup-head-' + name);
    if (!body || !head) return;
    const opened = !body.classList.toggle('collapsed');
    head.classList.toggle('open', opened);
  }

  function expandGroupFor(link) {
    const body = link.closest('.sidebar-group-body');
    if (!body) return;
    body.classList.remove('collapsed');
    const head = document.getElementById('sgroup-head-' + body.id.replace('sgroup-', ''));
    if (head) head.classList.add('open');
  }

  /* 그룹 헤더 배지: 하위 카운트 합산 (접혀 있어도 현황 파악 가능) */
  function updateGroupBadges() {
    document.querySelectorAll('.sidebar-group-body').forEach(body => {
      const badge = document.getElementById('sgroup-badge-' + body.id.replace('sgroup-', ''));
      if (!badge) return;
      let sum = 0;
      body.querySelectorAll('.sidebar-link .badge').forEach(b => {
        const v = parseInt(String(b.textContent).replace(/[,%]/g, ''), 10);
        if (!isNaN(v) && b.id !== 'sidebar-purple-cov') sum += v;
      });
      badge.textContent = sum.toLocaleString();
      badge.classList.toggle('d-none', sum === 0);
    });
  }
  setInterval(updateGroupBadges, 3000);

  /* ─────────────────── 패널 전환 ─────────────────── */
  function showPanel(name) {
    document.querySelectorAll('.panel-section').forEach(p => p.classList.add('d-none'));
    const target = document.getElementById('panel-' + name);
    if (target) target.classList.remove('d-none');

    document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
    const link = document.querySelector(`[data-panel="${name}"]`);
    if (link) { link.classList.add('active'); expandGroupFor(link); }

    closeSidebar();   // 모바일: 패널 선택 시 드로어 닫기

    if (name === 'overview') setTimeout(() => {
      initMap();
      if (typeof renderLiveStream === 'function') renderLiveStream();
      if (typeof renderTopAttackers === 'function') renderTopAttackers();
      if (typeof renderThreatTypeChart === 'function') renderThreatTypeChart();
    }, 50);
    if (name === 'traffic') initTrafficCharts();
    if (name === 'alerts') loadAlerts();
    if (name === 'alert-history') loadAlertHistory();
    if (name === 'packets') initPacketsTable();
    if (name === 'sysmon') initSysmonTable();
    if (name === 'ml') { setTimeout(initMLCharts, 50); loadDecisionSupport(); }
    if (name === 'mitre') loadMitreMatrix();
    if (name === 'campaigns') loadCampaigns();
    if (name === 'siem-correlation') loadSiemCorrelation();
    if (name === 'threat-intel') loadThreatIntel();
    if (name === 'siem') loadSiem();
    if (name === 'syslog') loadSyslog();
    if (name === 'honeypot') loadHoneypot();
    if (name === 'snort') loadSnort(true);
    if (name === 'authlog') loadAuthlog();
    if (name === 'reputation') loadReputation();
    if (name === 'edr') loadEdr();
    if (name === 'network') loadNetwork();
    if (name === 'sigma') loadSigma();
    if (name === 'yara') loadYara();
    if (name === 'hunt') loadHunts();
    if (name === 'labeling') loadLabeling();
    if (name === 'vulnscan') loadVulnScan();
    if (name === 'fuzz') loadFuzz();
    if (name === 'patch') loadPatch();
    if (name === 'notify') loadNotify();
    if (name === 'report') loadReport();
    if (name === 'purple') loadPurple();
    if (name === 'soar') loadSoar();
    if (name === 'incidents') loadIncidents();
    if (name === 'myinfo') loadMyInfo();
    if (name === 'metrics') loadMetrics();
    if (name === 'audit') loadAudit();
    if (name === 'watchlist') loadWatchlist();
    if (name === 'health') { loadHealth(); startHealthAuto(); }
    else if (typeof stopHealthAuto === 'function') stopHealthAuto();
  }

  /* ════════════════════ 내 정보 (System Info) ════════════════════ */
  async function loadMyInfo(force) {
    try {
      const res  = await fetch('/api/system/info' + (force ? '?t=' + Date.now() : ''));
      const data = await res.json();
      renderMyInfo(data);
    } catch (e) {
      console.error('[myinfo] load failed', e);
    }
  }

  function renderMyInfo(d) {
    const host = d.host || {}, net = d.network || {}, res = d.resources || {};
    const geo  = net.geo || {};

    document.getElementById('myinfo-last-update').textContent = '최종 조회 ' + (d.timestamp || '');

    // 공인 IP
    document.getElementById('myinfo-public-ip').textContent = net.public_ip || '조회 실패';
    if (geo && geo.country) {
      document.getElementById('myinfo-geo').innerHTML =
        `<i class="fa fa-location-dot me-1"></i>${escapeHtml(geo.country)} · ${escapeHtml(geo.city || geo.regionName || '')}`;
      document.getElementById('myinfo-isp').textContent = geo.isp || geo.org || 'ISP —';
    } else {
      document.getElementById('myinfo-geo').innerHTML = '<i class="fa fa-location-dot me-1"></i>' + (net.public_ip ? '위치 정보 없음' : '외부 접근 불가');
      document.getElementById('myinfo-isp').textContent = 'ISP —';
    }

    // 사설 IP
    document.getElementById('myinfo-private-ip').textContent = net.primary_private_ip || '—';
    const extra = (net.private_ips || []).slice(1);
    document.getElementById('myinfo-private-ip-all').textContent =
      extra.length ? '보조 ' + extra.join(', ') : '단일 IP';

    // 호스트
    document.getElementById('myinfo-hostname').textContent = host.hostname || '—';
    document.getElementById('myinfo-username').textContent = host.username ? '@' + host.username : '—';
    document.getElementById('myinfo-mac').textContent = host.mac || '—';

    // 시스템 grid (key-value 리스트)
    const osLine = `${host.os || ''} ${host.os_release || ''}`.trim();
    const sysRows = [
      ['fa-server',       '호스트명',    host.hostname || '—'],
      ['fa-globe',        'FQDN',         host.fqdn || '—'],
      ['fa-brands fa-windows', 'OS',     osLine || '—'],
      ['fa-tag',          'OS 버전',     host.os_version || '—'],
      ['fa-layer-group',  '플랫폼',      host.platform || '—'],
      ['fa-microchip',    '아키텍처',    host.architecture || '—'],
      ['fa-microchip',    'CPU',         host.processor || '—'],
      ['fa-brands fa-python', 'Python', host.python_version || '—'],
      ['fa-ethernet',     'MAC',         host.mac || '—'],
    ];
    document.getElementById('myinfo-system-grid').innerHTML = sysRows.map(([ic, k, v]) => `
      <div class="kv-row">
        <div class="kv-key"><i class="fa ${ic}"></i>${k}</div>
        <div class="kv-val font-monospace">${escapeHtml(v)}</div>
      </div>`).join('');

    // 리소스 (진행률 바)
    const uptime = res.uptime_sec ? formatUptime(res.uptime_sec) : '—';
    const bars = [
      barHtml('fa-gauge-high',  'CPU',     res.cpu_percent,
              res.cpu_percent != null ? res.cpu_percent + ' %' : '—',
              res.cpu_count ? res.cpu_count + ' core' : ''),
      barHtml('fa-memory',      '메모리',  res.mem_percent,
              (res.mem_used_mb != null)
                ? `${fmtMB(res.mem_used_mb)} / ${fmtMB(res.mem_total_mb)}` : '—',
              res.mem_percent != null ? res.mem_percent + ' %' : ''),
      barHtml('fa-hard-drive',  '디스크',  res.disk_percent,
              (res.disk_used_gb != null)
                ? `${res.disk_used_gb} / ${res.disk_total_gb} GB` : '—',
              res.disk_percent != null ? res.disk_percent + ' %' : ''),
    ].join('');
    const meta = `
      <div class="kv-row"><div class="kv-key"><i class="fa fa-power-off"></i>부팅 시각</div>
        <div class="kv-val font-monospace">${escapeHtml(res.boot_time || '—')}</div></div>
      <div class="kv-row"><div class="kv-key"><i class="fa fa-clock"></i>가동 시간</div>
        <div class="kv-val font-monospace">${escapeHtml(uptime)}</div></div>`;
    document.getElementById('myinfo-resource-box').innerHTML =
      `<div class="resource-bars">${bars}</div><div class="kv-grid mt-2">${meta}</div>`;

    // 인터페이스
    const ifaces = net.interfaces || [];
    const box = document.getElementById('myinfo-iface-list');
    if (!ifaces.length) {
      box.innerHTML = '<div class="kv-placeholder">인터페이스 정보 없음</div>';
    } else {
      box.innerHTML = `<div class="iface-grid">${ifaces.map(ifaceCard).join('')}</div>`;
    }
  }

  function barHtml(icon, label, percent, valText, rightText) {
    const pct = Math.max(0, Math.min(100, Number(percent) || 0));
    let cls = 'bar-low';
    if (pct >= 85) cls = 'bar-high';
    else if (pct >= 60) cls = 'bar-mid';
    return `
      <div class="res-item">
        <div class="res-head">
          <span><i class="fa ${icon} me-2 text-cyan"></i>${label}</span>
          <span class="font-monospace">${escapeHtml(valText)}</span>
        </div>
        <div class="res-bar"><div class="res-fill ${cls}" style="width:${pct}%"></div></div>
        <div class="res-foot">${escapeHtml(rightText || '')}</div>
      </div>`;
  }

  function ifaceCard(i) {
    const isUp = !!i.is_up;
    return `
      <div class="iface-card ${isUp ? 'up' : 'down'}">
        <div class="iface-head">
          <span class="iface-dot"></span>
          <span class="iface-name" title="${escapeHtml(i.name || '')}">${escapeHtml(i.name || '—')}</span>
          <span class="iface-status">${isUp ? 'UP' : 'DOWN'}</span>
        </div>
        <div class="iface-row"><span class="iface-k">IPv4</span><span class="iface-v font-monospace">${escapeHtml(i.ipv4 || '—')}</span></div>
        <div class="iface-row"><span class="iface-k">IPv6</span><span class="iface-v font-monospace" title="${escapeHtml(i.ipv6||'')}">${escapeHtml(i.ipv6 || '—')}</span></div>
        <div class="iface-row"><span class="iface-k">MAC</span><span class="iface-v font-monospace">${escapeHtml(i.mac || '—')}</span></div>
        <div class="iface-row"><span class="iface-k">속도</span><span class="iface-v">${i.speed_mbps ? i.speed_mbps + ' Mbps' : '—'}</span></div>
      </div>`;
  }

  function fmtMB(mb) {
    if (mb == null) return '—';
    return mb >= 1024 ? (mb / 1024).toFixed(1) + ' GB' : mb + ' MB';
  }

  function formatUptime(sec) {
    sec = Number(sec) || 0;
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    return (d ? d + '일 ' : '') + (h ? h + '시간 ' : '') + m + '분';
  }

  /* ── 패널 딥링크 ──
     사이드바 링크는 href="#alerts" 를 갖고 있었지만 클릭 핸들러가 preventDefault
     만 하고 주소를 바꾸지 않았다. 그래서 주소창은 언제나 첫 화면을 가리켰고,
     동료에게 "MITRE 매트릭스 좀 봐" 하며 링크를 줄 수가 없었다. 뒤로가기도
     대시보드를 통째로 벗어났다. 관제는 인수인계로 굴러가는 일이라 화면을
     가리키는 주소가 있어야 한다. */
  function panelExists(name) {
    return !!(name && document.getElementById('panel-' + name));
  }

  function panelFromHash() {
    const name = decodeURIComponent((location.hash || '').replace(/^#/, '')).trim();
    return panelExists(name) ? name : null;
  }

  document.querySelectorAll('.sidebar-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const name = link.dataset.panel;
      showPanel(name);
      // 같은 패널을 다시 누를 때 이력을 쌓지 않는다.
      if (panelFromHash() !== name) history.pushState(null, '', '#' + name);
    });
  });

  // 뒤로/앞으로, 그리고 주소창에 직접 입력한 해시.
  window.addEventListener('popstate', () => showPanel(panelFromHash() || 'overview'));
  window.addEventListener('hashchange', () => {
    const name = panelFromHash();
    if (name) showPanel(name);
  });

  // 첫 진입에 해시가 있으면 그 패널로 연다.
  // **모든 스크립트가 로드된 뒤에** 열어야 한다. 이 파일은 01 번이라 패널 로더
  // (loadMitreMatrix 등)를 정의하는 뒤 파일들보다 먼저 실행되고, 지금 showPanel 을
  // 부르면 아직 없는 함수를 불러 ReferenceError 로 죽는다.
  function openInitialPanel() {
    const name = panelFromHash();
    if (name && name !== 'overview') showPanel(name);
  }
  if (document.readyState === 'complete') openInitialPanel();
  else window.addEventListener('load', openInitialPanel, { once: true });

  /* ─────────────────── 시간 표시 ─────────────────── */
  setInterval(() => {
    if (document.hidden) return;
    document.getElementById('current-time').textContent =
      new Date().toLocaleString('ko-KR', { hour12: false });
  }, 1000);

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    closeSidebar, escapeHtml, isPanelVisible, loadMyInfo, protoColor, sevBadge, showPanel,
    socket, threatColor, toggleGroup, toggleSidebar,
  });
})();
