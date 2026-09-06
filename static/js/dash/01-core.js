/* dashboard/01-core.js — 유틸·사이드바·패널전환·내 정보·시간
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
(function () {
  /* ══════════════════════════════════════════
     SOC Dashboard — Main JS
  ══════════════════════════════════════════ */

  /* ── 키 기반 목록 조정(reconcile) ──
     실시간 목록(라이브 스트림·TOP 공격자·SIEM 이벤트·SOAR 이력)은 갱신마다
     innerHTML 로 통째로 다시 만들고 있었다. 분석가가 한 행을 읽거나 텍스트를
     드래그하는 중에 알림이 오면 그 노드가 버려져 **선택·포커스·스크롤이
     날아간다.** 관제 도구에서 매일 겪는 짜증이다.

     여기서는 항목마다 키를 두고, 이미 있는 노드는 **그대로 두고 자리만 옮긴다.**
     새 항목만 만들고, 사라진 항목만 지운다. 바뀌지 않은 노드는 정체성을 유지
     하므로 그 안의 선택·포커스가 살아남는다.

     items:  렌더할 배열(원하는 순서)
     keyOf:  item → 안정적인 문자열 키
     render: item → HTML 문자열 (새 항목·내용이 바뀐 항목에만 호출)
     opts.sig: item → 내용 서명. 같은 키라도 서명이 바뀌면 다시 그린다(기본: 키만). */
  function reconcileList(container, items, keyOf, render, opts) {
    if (!container) return;
    const sigOf = (opts && opts.sig) || (() => '');
    const byKey = new Map();
    for (const el of container.children) {
      if (el.dataset && el.dataset.key !== undefined) byKey.set(el.dataset.key, el);
    }
    const wanted = new Set();
    const build = item => {
      const tmp = document.createElement('template');
      tmp.innerHTML = render(item).trim();
      return tmp.content.firstElementChild;
    };
    // cursor = "다음 항목이 놓여야 할 자리 앞의 노드". 불변식: 항목을 놓은 뒤에는
    // 항상 cursor = el.nextElementSibling. 이전 구현은 내용 교체(replaceWith) 뒤
    // cursor 가 떨어져 나간 옛 노드를 가리킨 채 남아 insertBefore 가
    // NotFoundError 를 냈다 — 브라우저 테스트가 잡았다.
    let cursor = container.firstElementChild;
    for (const item of items) {
      const key = String(keyOf(item));
      const sig = String(sigOf(item));
      wanted.add(key);
      let el = byKey.get(key);
      if (el && el.dataset.sig !== sig) {
        // 내용이 바뀐 항목: 그 노드만 교체(이웃은 살린다)
        const fresh = build(item);
        if (fresh) {
          fresh.dataset.key = key; fresh.dataset.sig = sig;
          if (cursor === el) cursor = fresh;
          el.replaceWith(fresh); el = fresh; byKey.set(key, el);
        }
      } else if (!el) {
        el = build(item);
        if (!el) continue;
        el.dataset.key = key; el.dataset.sig = sig;
      }
      // 원하는 순서대로 커서 앞에 놓는다. 이미 제자리면 아무것도 안 한다.
      if (el !== cursor) container.insertBefore(el, cursor);
      cursor = el.nextElementSibling;
    }
    // 원하지 않는 나머지(오래된 항목·플레이스홀더) 제거
    for (const el of Array.from(container.children)) {
      if (!wanted.has(el.dataset.key)) el.remove();
    }
  }

  /* ── 토큰 값 읽기 ──
     Chart.js 는 캔버스에 그리고 SVG 속성은 문자열을 받으므로 `var(--x)` 를
     그대로 넘길 수 없다. 그래서 색을 하드코딩해 두었더니 팔레트를 블랙으로
     바꿀 때 차트만 옛 색으로 남았다. 여기서 계산된 값을 읽어 넘긴다.
     한 번 읽은 값은 캐시한다(테마 전환이 없는 화면이라 안전하다). */
  const _cssVarCache = new Map();

  function cssVar(name, fallback) {
    if (_cssVarCache.has(name)) return _cssVarCache.get(name);
    let v = '';
    try {
      v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    } catch (e) { /* 계산 불가 환경 — fallback 으로 */ }
    const out = v || fallback || '';
    if (v) _cssVarCache.set(name, out);
    return out;
  }

  /* ── 키보드 조작 ──
     클릭 가능한 카드·단계 표시가 div/span 으로 만들어져 있어 마우스로만 쓸 수
     있었다. role="button" tabindex="0" 를 붙였으니 실제 버튼처럼 **Enter/Space
     로도 눌려야** 한다. 브라우저는 진짜 <button> 에만 그걸 해 준다. */
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
    const el = e.target;
    if (!el || el.getAttribute('role') !== 'button') return;
    if (el.tagName === 'BUTTON' || el.tagName === 'A') return;   // 기본 동작에 맡긴다
    e.preventDefault();          // Space 로 페이지가 스크롤되지 않게
    el.click();
  });

  /* Esc: 열려 있는 모바일 사이드바를 닫는다. 백드롭은 '바깥 클릭' 오버레이라
     탭 순서에 넣지 않았으므로, 키보드 사용자에겐 이 경로가 유일한 탈출구다. */
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && typeof closeSidebar === 'function') closeSidebar();
  });

  /* ── 보조기기 안내 ──
     라이브 스트림은 초당 여러 건이 흐른다. 거기에 aria-live 를 걸면 스크린리더가
     읽기를 멈추지 못해 화면을 쓸 수 없게 된다. 그래서 **의미 있는 사건만** 요약해
     이쪽으로 보낸다.

     announce(): 상태 갱신(polite) — 읽던 것을 끊지 않고 틈에 끼워 읽는다.
     alarm():    즉시 알림(assertive) — 읽던 것을 끊는다. CRITICAL 과 오류만.

     쏟아질 때를 대비해 창(window) 안에서 묶는다. CRITICAL 이 10초에 12건 오면
     12번 말하는 대신 "심각 알림 12건" 으로 한 번 말한다. */
  const _annQueue = { polite: [], assertive: [] };
  let _annTimer = { polite: null, assertive: null };

  function _flushAnn(kind) {
    const id = kind === 'assertive' ? 'a11y-alarm' : 'a11y-announcer';
    const box = document.getElementById(id);
    _annTimer[kind] = null;
    const items = _annQueue[kind].splice(0);
    if (!box || !items.length) return;
    // 같은 문구가 반복되면 건수로 접는다.
    const counts = new Map();
    items.forEach(t => counts.set(t, (counts.get(t) || 0) + 1));
    const text = [...counts.entries()]
      .map(([t, n]) => (n > 1 ? `${t} ${n}건` : t)).join('. ');
    // 같은 문자열을 다시 넣으면 스크린리더가 변화를 감지하지 못한다.
    box.textContent = '';
    setTimeout(() => { box.textContent = text; }, 30);
  }

  function _queueAnn(kind, text, waitMs) {
    if (!text) return;
    _annQueue[kind].push(String(text));
    if (_annTimer[kind]) return;
    _annTimer[kind] = setTimeout(() => _flushAnn(kind), waitMs);
  }

  function announce(text) { _queueAnn('polite', text, 1500); }
  function alarm(text)    { _queueAnn('assertive', text, 800); }

  /* ── 표 라이브러리 지연 로드 ──
     jQuery + DataTables(합 175KB + CSS 12KB)는 표 3개(알림·패킷·Sysmon)에서만
     쓰인다. 첫 화면인 AI 관제 센터에는 표가 없으므로, 표 패널을 처음 열 때
     받아온다. 여러 표가 동시에 요청해도 프라미스를 공유해 한 번만 받는다. */
  let tableLibsPromise = null;

  function loadCss(href) {
    return new Promise(resolve => {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = href;
      link.onload = link.onerror = () => resolve();   // 실패해도 표는 뜬다
      document.head.appendChild(link);
    });
  }

  function ensureTableLibs() {
    if (window.jQuery && jQuery.fn && jQuery.fn.dataTable) return Promise.resolve(true);
    if (!tableLibsPromise) {
      tableLibsPromise = loadScript('/static/vendor/jquery/jquery-3.7.1.min.js')
        .then(() => loadScript('/static/vendor/datatables/jquery.dataTables.min.js'))
        .then(() => loadScript('/static/vendor/datatables/dataTables.bootstrap5.min.js'))
        .then(() => loadCss('/static/vendor/datatables/dataTables.bootstrap5.min.css'))
        .then(() => { configureDataTables(); return true; })
        .catch(err => {
          tableLibsPromise = null;          // 다음에 다시 시도할 수 있게
          console.warn('[SOC] 표 라이브러리 로드 실패', err);
          return false;
        });
    }
    return tableLibsPromise;
  }

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const tag = document.createElement('script');
      tag.src = src;
      tag.onload = () => resolve();
      tag.onerror = () => reject(new Error(src));
      document.head.appendChild(tag);
    });
  }

  /* DataTables 공통 설정.

     언어: 대시보드는 전부 한국어인데 표 컨트롤만 "Show / entries / Search:" 였다.
     한 곳에서 기본값으로 정한다.

     ※ 알림 표에는 `language: { url: '' }` 가 들어가 있었다. DataTables 는 이걸
       "언어 파일을 이 URL 에서 받아라" 로 읽어 빈 URL(=현재 페이지)을 JSON 으로
       파싱하려다 실패했고, 그 바람에 길이 셀렉트의 `_MENU_` 가 치환되지 않아
       **옵션 없는 빈 상자**로 떴다. 색 문제로 보였지만 설정이 깨진 것이었다.

     컨트롤에 폼 유틸(.bg-dark 등)을 붙이는 이유: 이 저장소의 다른 폼 요소가
     모두 그 관례를 쓰는데 DT 가 만드는 컨트롤에는 없어서 혼자 달라 보였다. */
  function configureDataTables() {
    if (!(window.jQuery && jQuery.fn.dataTable)) return;
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
    // null/undefined 는 화면에 'null' 로 찍히지 않게 빈 문자열로(목적지 없는 알림이 26%).
    if (s == null) return '';
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
    item.setAttribute('role', 'alert');   // 오류는 읽던 것을 끊고 알려야 한다
    item.setAttribute('style',
      'background:#2d1416;border:1px solid var(--red);' +
      'color:var(--text-primary);border-radius:6px;padding:8px 10px;font-size:var(--fs-sm);' +
      'display:flex;gap:8px;align-items:flex-start;box-shadow:0 2px 8px rgba(0,0,0,.4)');
    item.innerHTML =
      '<i class="fa fa-triangle-exclamation" style="color:var(--red);margin-top:2px"></i>' +
      `<span style="flex:1;word-break:break-all">${escapeHtml(message)}</span>` +
      '<span class="api-err-count" style="color:var(--text-dim)">×1</span>' +
      '<button type="button" style="background:none;border:none;color:var(--text-dim);' +
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
    const m = { TCP:'#39d0d8', UDP:'#9d79f2', ICMP:'#e3b341', ARP:'#3fb950', OTHER:cssVar('--text-dim', '#94949b') };
    return m[p] || cssVar('--text-dim', '#94949b');
  }

  function threatColor(t) {
    const m = { DDOS:'#f85149', PORT_SCAN:'#f79000', BRUTE_FORCE:'#e3b341',
                 MALWARE_BEACON:'#f85149', DATA_EXFIL:'#f79000',
                 ARP_SPOOFING:'#9d79f2', DNS_TUNNELING:'#58a6ff', ANOMALY:cssVar('--text-dim', '#94949b') };
    return m[t] || cssVar('--text-dim', '#94949b');
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

  /* ─────────────────── 패널 지연 실체화 ───────────────────
     dashboard.html 은 개요만 실제 DOM 으로 내리고, 나머지 35개 패널은
     <template data-panel="이름"> 안에 담아 보낸다. template 내용은 문서 트리에
     속하지 않아(inert) 스타일 계산·레이아웃·getElementById 에 잡히지 않는다.
     처음 열 때 여기서 꺼내 놓으면 그 뒤로는 상주 패널과 똑같이 동작한다.

     패널 안 요소에 리스너를 달아야 하는 코드는 DOMContentLoaded 가 아니라
     onPanelReady(이름, fn) 을 쓴다 — 실체화 시점에 한 번 불러 준다.
     소켓 핸들러는 isPanelVisible() 이 "없는 패널 = 안 보임" 으로 답하므로
     실체화 여부를 알 필요가 없다. */
  const _panelReadyHooks = {};   // name -> [fn]

  function materializePanel(name) {
    if (document.getElementById('panel-' + name)) return true;
    const tpl = document.querySelector(`template[data-panel="${name}"]`);
    if (!tpl) return false;
    tpl.replaceWith(tpl.content);
    (_panelReadyHooks[name] || []).forEach(fn => {
      try { fn(); } catch (e) { console.error('panel hook 실패:', name, e); }
    });
    delete _panelReadyHooks[name];
    return true;
  }

  function onPanelReady(name, fn) {
    if (document.getElementById('panel-' + name)) { fn(); return; }
    (_panelReadyHooks[name] = _panelReadyHooks[name] || []).push(fn);
  }

  /* ─────────────────── 패널 전환 ─────────────────── */
  function showPanel(name) {
    materializePanel(name);
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
      ['fa-solid fa-window-restore', 'OS',     osLine || '—'],
      ['fa-tag',          'OS 버전',     host.os_version || '—'],
      ['fa-layer-group',  '플랫폼',      host.platform || '—'],
      ['fa-microchip',    '아키텍처',    host.architecture || '—'],
      ['fa-microchip',    'CPU',         host.processor || '—'],
      ['fa-solid fa-code', 'Python', host.python_version || '—'],
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
    if (!name || !/^[a-z-]+$/.test(name)) return false;
    return !!(document.getElementById('panel-' + name) ||
              document.querySelector(`template[data-panel="${name}"]`));
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
    alarm, announce, cssVar, ensureTableLibs, loadScript, reconcileList,
    closeSidebar, escapeHtml, isPanelVisible, loadMyInfo, materializePanel, onPanelReady,
    protoColor, sevBadge, showPanel,
    socket, threatColor, toggleGroup, toggleSidebar,
  });
})();
