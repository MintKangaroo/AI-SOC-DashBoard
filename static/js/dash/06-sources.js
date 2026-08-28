/* dashboard/06-sources.js — SIEM·SSH인증·IP평판·EDR·네트워크관제·퍼플팀
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
(function () {
  /* ════════════════════ SIEM — Splunk 스타일 이벤트 검색 ════════════════════ */
  let siemEventsBuffer = [];
  let _siemSources = [];
  let _siemRenderTimer = null;

  function loadSiem() {
    fetch('/api/integrations/siem')
      .then(r => r.json())
      .then(renderSiemStatus)
      .catch(() => {});
  }

  function renderSiemStatus(d) {
    const stats = d.stats || {};
    _siemSources = d.sources || [];
    const badge = document.getElementById('sidebar-siem-count');
    if (badge) badge.textContent = (stats.suspicious_events || 0).toLocaleString();
    setPipe('pipe-siem-total', stats.total_events);
    setPipe('pipe-siem-susp', stats.suspicious_events);
    siemEventsBuffer = d.events || [];
    renderSiemEvents();
  }

  // 검색어 매칭 (ip/요청/분류/소스/severity/suspicious 키워드)
  function _siemMatch(e, q) {
    if (!q) return true;
    q = q.toLowerCase();
    if (q === 'suspicious') return e.suspicious;
    return [e.ip, e.request, e.category, e.source, e.severity, String(e.status)]
      .some(v => (v || '').toString().toLowerCase().includes(q));
  }

  // 타임스탬프 → HH:MM 버킷 키
  function _siemMinute(ts) {
    const m = (ts || '').match(/(\d{2}):(\d{2}):\d{2}/);
    return m ? `${m[1]}:${m[2]}` : '--:--';
  }

  function _siemFiltered() {
    const q = document.getElementById('siem-search')?.value.trim() || '';
    const onlySusp = document.getElementById('siem-suspicious-only')?.checked;
    const mins = parseInt(document.getElementById('siem-timerange')?.value || '0');
    let evs = siemEventsBuffer.filter(e => _siemMatch(e, q) && (!onlySusp || e.suspicious));
    if (mins > 0) {
      const cutoff = Date.now() - mins * 60000;
      // 타임스탬프에 날짜가 제각각이라 상대 최근성은 버퍼 순서로 근사(최신이 앞)
      evs = evs.slice(0, Math.max(20, Math.round(evs.length * Math.min(1, mins / 60))));
    }
    return evs;
  }

  function renderSiemEvents() {
    const box = document.getElementById('siem-events');
    if (!box) return;
    const evs = _siemFiltered();
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('siem-result-count', evs.length);
    set('siem-suspicious', evs.filter(e => e.suspicious).length);
    set('siem-unique-ips', new Set(evs.map(e => e.ip)).size);
    set('siem-sources-ok', _siemSources.filter(s => s.exists).length);

    box.innerHTML = evs.length
      ? evs.slice(0, 200).map(siemRawEvent).join('')
      : '<div class="text-muted p-4 text-center small">일치하는 이벤트가 없습니다.</div>';

    renderSiemTimeline(evs);
    renderSiemFields(evs);
  }

  // Splunk raw event (행 클릭 시 필드 펼침)
  function siemRawEvent(e, idx) {
    const sev = e.severity || 'INFO';
    const sevColor = sev === 'CRITICAL' ? '#f85149' : sev === 'HIGH' ? '#f0a500'
                   : sev === 'MEDIUM' ? '#d29922' : e.suspicious ? '#f0a500' : '#3fb950';
    const raw = `${e.ip} - - [${e.timestamp}] "${e.request}" ${e.status}`;
    const fields = [
      ['host', e.source], ['src_ip', e.ip], ['status', e.status],
      ['severity', sev], ['category', e.category], ['suspicious', e.suspicious],
    ].map(([k, v]) => `<span class="spl-fv" onclick="siemSetSearch('${escapeHtml(String(v))}')">
        <span class="spl-fk">${k}</span>=<span class="spl-fvv">${escapeHtml(String(v))}</span></span>`).join('');
    return `
      <div class="spl-event ${e.suspicious ? 'spl-event-susp' : ''}" style="border-left-color:${sevColor}"
           onclick="this.classList.toggle('open')">
        <div class="spl-event-top">
          <span class="spl-ts">${escapeHtml(e.timestamp)}</span>
          <span class="spl-raw">${escapeHtml(raw)}</span>
          <span class="spl-sev" style="background:${sevColor}">${escapeHtml(sev)}</span>
        </div>
        <div class="spl-event-fields">${fields}</div>
      </div>`;
  }

  // 타임라인 히스토그램 (분당 이벤트 · 의심 스택)
  function renderSiemTimeline(evs) {
    const svg = document.getElementById('siem-timeline');
    if (!svg) return;
    const buckets = {};
    evs.forEach(e => {
      const k = _siemMinute(e.timestamp);
      (buckets[k] = buckets[k] || { total: 0, susp: 0 });
      buckets[k].total++; if (e.suspicious) buckets[k].susp++;
    });
    const keys = Object.keys(buckets).sort().slice(-40);
    if (!keys.length) { svg.innerHTML = ''; return; }
    const max = Math.max(...keys.map(k => buckets[k].total), 1);
    const W = svg.clientWidth || 900, H = 110, pad = 18, bw = (W - pad) / keys.length;
    let g = '';
    keys.forEach((k, i) => {
      const b = buckets[k], x = pad + i * bw, h = (b.total / max) * (H - 24);
      const hs = (b.susp / max) * (H - 24);
      g += `<rect x="${x + 1}" y="${H - 16 - h}" width="${Math.max(1, bw - 2)}" height="${h}" fill="#2b6cb0"><title>${k} · ${b.total}건</title></rect>`;
      if (hs > 0) g += `<rect x="${x + 1}" y="${H - 16 - hs}" width="${Math.max(1, bw - 2)}" height="${hs}" fill="#f85149"><title>${k} · 의심 ${b.susp}</title></rect>`;
    });
    // x축 라벨(양끝)
    g += `<text x="${pad}" y="${H - 3}" fill="#8b949e" font-size="9">${keys[0]}</text>`;
    g += `<text x="${W - 4}" y="${H - 3}" fill="#8b949e" font-size="9" text-anchor="end">${keys[keys.length - 1]}</text>`;
    g += `<text x="${pad - 4}" y="12" fill="#6e7681" font-size="9" text-anchor="end">${max}</text>`;
    svg.innerHTML = g;
  }

  // Splunk 필드 사이드바 (필드별 top 값 + 건수)
  function renderSiemFields(evs) {
    const box = document.getElementById('siem-fields');
    if (!box) return;
    const fieldDefs = [
      ['category', '분류', e => e.category],
      ['source', '소스', e => e.source],
      ['severity', '심각도', e => e.severity],
      ['src_ip', '출발지 IP', e => e.ip],
      ['status', '상태', e => String(e.status)],
    ];
    box.innerHTML = fieldDefs.map(([key, label, fn]) => {
      const counts = {};
      evs.forEach(e => { const v = fn(e); if (v != null && v !== '') counts[v] = (counts[v] || 0) + 1; });
      const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
      const distinct = Object.keys(counts).length;
      const vals = top.map(([v, c]) => `
        <div class="spl-field-val" onclick="siemSetSearch('${escapeHtml(v)}')">
          <span class="spl-field-v">${escapeHtml(v)}</span><span class="spl-field-c">${c}</span>
        </div>`).join('');
      return `<div class="spl-field">
        <div class="spl-field-name">${escapeHtml(label)} <span class="spl-field-distinct">${distinct}</span></div>
        ${vals || '<div class="spl-field-val text-muted">—</div>'}
      </div>`;
    }).join('');
  }

  function siemSetSearch(v) {
    const inp = document.getElementById('siem-search');
    if (inp) { inp.value = v; renderSiemEvents(); }
    event && event.stopPropagation && event.stopPropagation();
  }

  socket.on('siem_event', e => {
    siemEventsBuffer.unshift(e);
    while (siemEventsBuffer.length > 500) siemEventsBuffer.pop();
    const bump = (id, n) => {
      const el = document.getElementById(id);
      if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g, '')) || 0) + n).toLocaleString();
    };
    bump('pipe-siem-total', 1);
    if (e.suspicious) {
      bump('sidebar-siem-count', 1);
      bump('pipe-siem-susp', 1);
      pushLive('siem', e.severity,
        `<b>${escapeHtml(e.category)}</b> <span class="lv-ip">${escapeHtml(e.ip)}</span> ` +
        `<span class="text-muted">(${escapeHtml(e.source)})</span>`);
    }
    // 패널 열려 있을 때만, 그리고 rAF 스로틀로 재렌더(렉 방지)
    const panel = document.getElementById('panel-siem');
    if (panel && !panel.classList.contains('d-none') && !_siemRenderTimer) {
      _siemRenderTimer = setTimeout(() => { _siemRenderTimer = null; renderSiemEvents(); }, 800);
    }
  });

  socket.on('siem_status', renderSiemStatus);

  /* ════════════════════ SSH 인증 로그 ════════════════════ */
  let authEventsBuffer = [];

  const AUTH_TYPE_META = {
    failed:   { badge: 'bg-danger',            label: '실패' },
    invalid:  { badge: 'bg-orange',            label: '무효계정' },
    preauth:  { badge: 'bg-warning text-dark', label: '조기종료' },
    accepted: { badge: 'bg-success',           label: '성공' },
  };

  function loadAuthlog() {
    fetch('/api/authlog').then(r => r.json()).then(renderAuthlog).catch(() => {});
  }

  function renderAuthlog(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('auth-total', stats.total);
    set('auth-failed', stats.failed);
    set('auth-invalid', stats.invalid);
    set('auth-accepted', stats.accepted);
    set('auth-brute', stats.brute_alerts);

    const modeBadge = document.getElementById('authlog-mode-badge');
    const modeNote = document.getElementById('authlog-mode-note');
    if (modeBadge) {
      const real = stats.mode === 'real';
      modeBadge.textContent = real ? '실시간 (auth.log)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
      modeBadge.style.background = real ? 'var(--green)' : '#30363d';
      modeBadge.style.color = real ? '#001417' : '#e6edf3';
    }
    if (modeNote) modeNote.textContent = stats.mode === 'demo'
      ? '(현재 데모 데이터 — 실서버에선 실제 auth.log를 읽습니다)' : '';

    const topBox = document.getElementById('auth-top-ips');
    if (topBox) {
      const top = stats.top_ips || [];
      topBox.innerHTML = top.length
        ? top.map(([ip, cnt], i) => `
            <div class="d-flex justify-content-between p-1 border-bottom border-secondary small">
              <span class="font-monospace" style="color:#e6edf3">${i + 1}. ${escapeHtml(ip)}</span>
              <span class="text-warning">${cnt.toLocaleString()}회</span>
            </div>`).join('')
        : '<div class="text-muted p-2">데이터 없음</div>';
    }

    authEventsBuffer = d.events || [];
    renderAuthEvents();

    svgDonut('auth-donut', [
      { label: '성공', value: stats.accepted || 0, color: '#3fb950' },
      { label: '실패', value: stats.failed || 0, color: '#f85149' },
      { label: '무효 계정', value: stats.invalid || 0, color: '#f0a500' },
    ], (stats.total || 0).toLocaleString(), '총 시도');
  }

  function authEventRow(e) {
    const meta = AUTH_TYPE_META[e.type] || { badge: 'bg-secondary', label: e.type };
    return `
      <tr ${e.type !== 'accepted' ? 'style="background:rgba(248,81,73,.06)"' : ''}>
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(e.timestamp)}</td>
        <td class="small"><span class="badge ${meta.badge}" style="font-size:9px">${meta.label}</span></td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(e.user || '-')}</td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(e.ip)}</td>
        <td class="small" style="color:#e6edf3">${e.port || '-'}</td>
      </tr>`;
  }

  function renderAuthEvents() {
    const tbody = document.getElementById('auth-events-tbody');
    if (!tbody) return;
    const failOnly = document.getElementById('auth-fail-only')?.checked;
    const rows = authEventsBuffer.filter(e => !failOnly || e.type !== 'accepted').slice(0, 200);
    tbody.innerHTML = rows.length
      ? rows.map(authEventRow).join('')
      : '<tr><td colspan="5" class="text-muted text-center p-3">이벤트 없음</td></tr>';
  }

  socket.on('auth_event', e => {
    authEventsBuffer.unshift(e);
    while (authEventsBuffer.length > 500) authEventsBuffer.pop();
    const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
    bump('auth-total', 1);
    if (e.type === 'accepted') bump('auth-accepted', 1);
    else if (e.type === 'invalid') bump('auth-invalid', 1);
    else bump('auth-failed', 1);
    // 실패/무효/성공 모두 통합 라이브 스트림에 (성공은 info)
    const sev = e.type === 'accepted' ? 'info' : 'medium';
    const label = (AUTH_TYPE_META[e.type] || {}).label || e.type;
    pushLive('auth', sev,
      `<b>SSH ${escapeHtml(label)}</b> 계정 ${escapeHtml(e.user || '-')} ` +
      `<span class="lv-ip">${escapeHtml(e.ip)}</span>`);
    // 사이드바 배지: 실패/무효 누적
    if (e.type !== 'accepted') {
      const badge = document.getElementById('sidebar-auth-count');
      if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
    }
    if (!document.getElementById('panel-authlog')?.classList.contains('d-none')) {
      renderAuthEvents();
    }
  });

  /* ════════════════════ IP 평판 (AbuseIPDB) ════════════════════ */
  let repEventsBuffer = [];
  let repMinScore = 75;

  function loadReputation() {
    fetch('/api/integrations/abuseipdb').then(r => r.json()).then(renderReputation).catch(() => {});
  }

  function repScoreBadge(score) {
    score = score || 0;
    let cls = 'bg-success', txt = '#001417';
    if (score >= repMinScore) { cls = 'bg-danger'; txt = '#fff'; }
    else if (score >= 25) { cls = 'bg-warning'; txt = '#1a1a1a'; }
    return `<span class="badge ${cls}" style="color:${txt};font-size:10px">${score}/100</span>`;
  }

  function renderReputation(d) {
    const stats = d.stats || {};
    repMinScore = d.min_score || 75;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('rep-total', stats.total_checks);
    set('rep-malicious', stats.malicious);
    set('rep-api-calls', stats.api_calls);
    set('rep-cache-hits', stats.cache_hits);
    set('rep-cache-size', d.cache_size);
    const minEl = document.getElementById('rep-min-score');
    if (minEl) minEl.textContent = repMinScore;

    const badge = document.getElementById('rep-mode-badge');
    const note = document.getElementById('rep-mode-note');
    if (badge) {
      const real = stats.mode === 'abuseipdb';
      badge.textContent = real ? '실조회 (AbuseIPDB)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
      badge.style.background = real ? 'var(--green)' : '#30363d';
      badge.style.color = real ? '#001417' : '#e6edf3';
    }
    if (note) note.textContent = stats.mode === 'demo'
      ? '(API 키 없음 — 데모 점수. .env ABUSEIPDB_API_KEY 설정 시 실조회)' : '';

    repEventsBuffer = d.recent || [];
    renderRepEvents();

    const buckets = [0, 0, 0, 0];
    (d.recent || []).forEach(r => {
      const s = r.score || 0;
      buckets[s >= 75 ? 3 : s >= 50 ? 2 : s >= 25 ? 1 : 0]++;
    });
    svgHBars('rep-bars', [
      { label: '악성 75+', value: buckets[3], color: '#f85149' },
      { label: '주의 50-74', value: buckets[2], color: '#f0a500' },
      { label: '낮음 25-49', value: buckets[1], color: '#d29922' },
      { label: '양호 0-24', value: buckets[0], color: '#3fb950' },
    ], '개');
  }

  function repRow(r) {
    const src = r.source === 'abuseipdb' ? 'AbuseIPDB' : (r.source === 'demo' ? '데모' : r.source);
    return `
      <tr ${(r.score || 0) >= repMinScore ? 'style="background:rgba(248,81,73,.08)"' : ''}>
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((r.checked_at || '').slice(11))}</td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(r.ip)}</td>
        <td>${repScoreBadge(r.score)}</td>
        <td class="small" style="color:#e6edf3">${(r.total_reports || 0).toLocaleString()}</td>
        <td class="small" style="color:#e6edf3">${escapeHtml(r.country || '-')}</td>
        <td class="small text-muted">${escapeHtml(src)}</td>
      </tr>`;
  }

  function renderRepEvents() {
    const tbody = document.getElementById('rep-events-tbody');
    if (!tbody) return;
    tbody.innerHTML = repEventsBuffer.length
      ? repEventsBuffer.slice(0, 100).map(repRow).join('')
      : '<tr><td colspan="6" class="text-muted text-center p-3">아직 조회한 외부 IP가 없습니다</td></tr>';
  }

  function checkReputation() {
    const inp = document.getElementById('rep-check-input');
    const box = document.getElementById('rep-check-result');
    const ip = (inp?.value || '').trim();
    if (!ip) return;
    if (box) box.innerHTML = '<span class="text-muted">조회 중...</span>';
    fetch('/api/reputation/check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    }).then(r => r.json()).then(r => {
      if (!box) return;
      if (r.error) { box.innerHTML = `<span class="text-danger">${escapeHtml(r.error)}</span>`; return; }
      if (r.source === 'internal') {
        box.innerHTML = `<span class="text-info">${escapeHtml(r.ip)} — 내부/Tailscale IP (조회 제외)</span>`;
        return;
      }
      const mal = (r.score || 0) >= repMinScore;
      box.innerHTML = `
        <div class="p-1">
          <div class="mb-1">${repScoreBadge(r.score)} <b class="font-monospace ms-1">${escapeHtml(r.ip)}</b>
            ${mal ? '<span class="text-danger ms-1">악성</span>' : '<span class="text-success ms-1">양호</span>'}</div>
          <div class="small text-muted">신고 ${(r.total_reports||0).toLocaleString()}건 · 국가 ${escapeHtml(r.country||'?')}
            · ISP ${escapeHtml(r.isp||'?')}</div>
          <div class="small text-muted">${escapeHtml(r.usage_type||'')}${r.last_reported ? ' · 최근신고 '+escapeHtml(r.last_reported.slice(0,10)) : ''}</div>
        </div>`;
      // 조회 결과를 최근 목록/스트림에도 반영
      repEventsBuffer.unshift(r);
      renderRepEvents();
    }).catch(() => { if (box) box.innerHTML = '<span class="text-danger">조회 실패</span>'; });
  }

  socket.on('ip_reputation', r => {
    if (!r || r.source === 'internal') return;
    repEventsBuffer.unshift(r);
    while (repEventsBuffer.length > 100) repEventsBuffer.pop();
    const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
    bump('rep-total', 1);
    if ((r.score || 0) >= repMinScore) {
      bump('rep-malicious', 1);
      const rbadge = document.getElementById('sidebar-rep-count');
      if (rbadge) rbadge.textContent = ((parseInt(rbadge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
      pushLive('rep', 'high',
        `<b>악성 IP 평판</b> <span class="lv-ip">${escapeHtml(r.ip)}</span> ` +
        `신뢰점수 ${r.score}/100 · 신고 ${(r.total_reports||0).toLocaleString()}건`);
    }
    if (!document.getElementById('panel-reputation')?.classList.contains('d-none')) {
      renderRepEvents();
    }
  });

  /* ════════════════════ EDR (AI 엔드포인트) ════════════════════ */
  let edrDetBuffer = [];

  function sevColor(sev) {
    return { CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--yellow, #d29922)', LOW: '#8b949e' }[sev] || '#8b949e';
  }
  function riskBadge(risk) {
    risk = risk || 0;
    let cls = 'bg-success', txt = '#001417';
    if (risk >= 70) { cls = 'bg-danger'; txt = '#fff'; }
    else if (risk >= 40) { cls = 'bg-warning'; txt = '#1a1a1a'; }
    return `<span class="badge ${cls}" style="color:${txt};font-size:10px">${risk}</span>`;
  }

  function loadEdr() {
    fetch('/api/integrations/edr').then(r => r.json()).then(renderEdr).catch(() => {});
  }

  function renderEdr(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('edr-proc-count', stats.process_count);
    set('edr-critical', stats.critical);
    set('edr-high', stats.high);
    set('edr-detections', stats.detections);
    set('edr-responses', stats.responses);
    const hostEl = document.getElementById('edr-host');
    if (hostEl) hostEl.textContent = d.host || '-';

    const badge = document.getElementById('edr-mode-badge');
    const note = document.getElementById('edr-mode-note');
    if (badge) {
      const real = stats.mode === 'real';
      badge.textContent = real ? '실센서 (psutil)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
      badge.style.background = real ? 'var(--green)' : '#30363d';
      badge.style.color = real ? '#001417' : '#e6edf3';
    }
    if (note) note.textContent = stats.mode === 'demo'
      ? '(현재 데모 프로세스 — 실서버에선 실제 실행 프로세스를 감시합니다)' : '';

    edrDetBuffer = d.detections || [];
    renderEdrDetections();
    drawEdrFlow(d);

    const ptb = document.getElementById('edr-proc-tbody');
    if (ptb) {
      const procs = (d.processes || []).filter(p => (p.risk || 0) > 0).slice(0, 40);
      ptb.innerHTML = procs.length
        ? procs.map(p => `
          <tr>
            <td>${riskBadge(p.risk)}</td>
            <td class="small font-monospace" style="color:#e6edf3">${p.pid}</td>
            <td class="small" style="color:#e6edf3" title="${escapeHtml(p.cmdline || '')}">${escapeHtml(p.name)}</td>
            <td class="small text-muted">${escapeHtml(p.user || '-')}</td>
          </tr>`).join('')
        : '<tr><td colspan="4" class="text-muted text-center p-3">위험 프로세스 없음 (정상)</td></tr>';
    }
  }

  // Falcon 스타일 프로세스 공격 흐름도 (SVG) — 부모→프로세스→IOA 체인
  function drawEdrFlow(d) {
    const svg = document.getElementById('edr-flow');
    if (!svg) return;
    const dets = (d.detections || []).slice(0, 5);
    const W = svg.clientWidth || 640;
    const rowH = 54, topPad = 12;
    const H = Math.max(120, topPad * 2 + dets.length * rowH);
    svg.setAttribute('height', H);

    if (!dets.length) {
      svg.innerHTML = `<text x="${W / 2}" y="60" text-anchor="middle" font-size="12" fill="#8b949e">탐지된 위협 프로세스가 없습니다 (정상)</text>`;
      return;
    }

    const riskColor = r => r >= 70 ? '#f85149' : (r >= 40 ? '#f0a500' : '#8b949e');
    const bw = 150, bh = 34, x0 = 8, x1 = x0 + bw + 60, x2 = x1 + bw + 60;

    const box = (x, y, w, title, sub, col) => `
      <rect x="${x}" y="${y}" width="${w}" height="${bh}" rx="7" fill="#0d1117" stroke="${col}" stroke-width="1.8"/>
      <text x="${x + 9}" y="${y + 14}" font-size="11" font-weight="700" fill="#e6edf3">${escapeHtml((title || '').slice(0, 22))}</text>
      <text x="${x + 9}" y="${y + 27}" font-size="9" font-family="monospace" fill="#8b949e">${escapeHtml((sub || '').slice(0, 26))}</text>`;
    const arrow = (xa, xb, y) => `<line x1="${xa}" y1="${y}" x2="${xb}" y2="${y}" stroke="#484f58" stroke-width="2" marker-end="url(#edr-arw)"/>`;

    let rows = '';
    dets.forEach((det, i) => {
      const y = topPad + i * rowH;
      const yc = y + bh / 2;
      const col = riskColor(det.risk);
      rows += box(x0, y, bw, det.parent || '?', '부모 프로세스', '#484f58');
      rows += arrow(x0 + bw, x1, yc);
      rows += box(x1, y, bw, `${det.process} (${det.pid})`, det.cmdline || '', col);
      rows += arrow(x1 + bw, x2, yc);
      // IOA/severity 노드
      rows += `<rect x="${x2}" y="${y}" width="${bw}" height="${bh}" rx="7" fill="${col}22" stroke="${col}" stroke-width="1.8"/>
        <text x="${x2 + 9}" y="${y + 14}" font-size="10.5" font-weight="700" fill="${col}">${escapeHtml(det.severity)} · 위험 ${det.risk}</text>
        <text x="${x2 + 9}" y="${y + 27}" font-size="9" fill="#c9d1d9">${escapeHtml((det.mitre || '') + ' ' + (det.rule || '').replace('IOA-', ''))}</text>`;
    });
    svg.innerHTML = `<defs><marker id="edr-arw" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#484f58"/></marker></defs>${rows}`;
  }

  function edrDetRow(det) {
    return `
      <tr style="background:rgba(248,81,73,${det.severity === 'CRITICAL' ? '.10' : '.05'})">
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((det.timestamp || '').slice(11))}</td>
        <td>${riskBadge(det.risk)}</td>
        <td class="small" style="color:#e6edf3" title="${escapeHtml(det.cmdline || '')}">
          <span class="font-monospace">${escapeHtml(det.process)}</span>
          <span class="text-muted">(${det.pid})</span></td>
        <td class="small" style="color:${sevColor(det.severity)}">${escapeHtml(det.description)}</td>
        <td class="small"><span class="badge bg-dark">${escapeHtml(det.mitre || '-')}</span></td>
        <td><button class="btn btn-xs btn-outline-danger" onclick="edrKill(${det.pid})" title="프로세스 격리">
          <i class="fa fa-ban"></i></button></td>
      </tr>`;
  }

  function renderEdrDetections() {
    const tbody = document.getElementById('edr-detections-tbody');
    if (!tbody) return;
    tbody.innerHTML = edrDetBuffer.length
      ? edrDetBuffer.slice(0, 60).map(edrDetRow).join('')
      : '<tr><td colspan="6" class="text-muted text-center p-3">탐지된 위협 없음</td></tr>';
  }

  function edrKill(pid) {
    if (!confirm(`PID ${pid} 프로세스를 격리(종료)할까요?\n(simulate 모드면 기록만, 시스템/대시보드 프로세스는 안전장치로 보호)`)) return;
    fetch('/api/edr/kill', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid })
    }).then(r => r.json()).then(r => {
      alert(r.ok ? `대응 완료: ${r.detail}` : `대응 보류: ${r.detail}`);
    }).catch(() => alert('대응 요청 실패'));
  }

  socket.on('edr_detection', det => {
    edrDetBuffer.unshift(det);
    while (edrDetBuffer.length > 300) edrDetBuffer.pop();
    const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
    bump('edr-detections', 1);
    if (det.severity === 'CRITICAL') bump('edr-critical', 1);
    else if (det.severity === 'HIGH') bump('edr-high', 1);
    const badge = document.getElementById('sidebar-edr-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
    pushLive('edr', (det.severity || 'high').toLowerCase(),
      `<b>EDR ${escapeHtml(det.description)}</b> ` +
      `<span class="font-monospace">${escapeHtml(det.process)}(${det.pid})</span> · 위험 ${det.risk}`);
    if (!document.getElementById('panel-edr')?.classList.contains('d-none')) {
      renderEdrDetections();
      drawEdrFlow({ detections: edrDetBuffer });
    }
  });

  socket.on('edr_status', s => {
    if (document.getElementById('panel-edr')?.classList.contains('d-none')) return;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('edr-proc-count', (s.stats || {}).process_count);
  });

  /* ════════════════════ 네트워크 관제 ════════════════════ */
  function loadNetwork() {
    fetch('/api/integrations/network').then(r => r.json()).then(renderNetwork).catch(() => {});
  }

  function renderNetwork(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('net-established', stats.established);
    set('net-listening', stats.listening_ports);
    set('net-peers', stats.external_peers);
    set('net-malicious', stats.malicious_conns);
    set('net-bandwidth', Math.round((stats.down_bps || 0) / 1024));

    const badge = document.getElementById('net-mode-badge');
    const note = document.getElementById('net-mode-note');
    if (badge) {
      const real = stats.mode === 'real';
      badge.textContent = real ? '실측 (psutil)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
      badge.style.background = real ? 'var(--green)' : '#30363d';
      badge.style.color = real ? '#001417' : '#e6edf3';
    }
    if (note) note.textContent = stats.mode === 'demo'
      ? '(현재 데모 데이터 — 실서버에선 실제 연결/포트/대역폭을 읽습니다)' : '';

    renderNetTargets(d.targets || []);

    const ct = document.getElementById('net-conns-tbody');
    if (ct) {
      const conns = d.connections || [];
      ct.innerHTML = conns.length
        ? conns.map(c => `
          <tr ${c.external ? 'style="background:rgba(247,144,0,.06)"' : ''}>
            <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(c.laddr)}</td>
            <td class="small font-monospace" style="color:${c.external ? 'var(--orange)' : '#e6edf3'}">${escapeHtml(c.raddr)}</td>
            <td class="small text-muted">${escapeHtml(c.status)}</td>
            <td class="small" style="color:#e6edf3">${escapeHtml(c.proc || '?')}</td>
          </tr>`).join('')
        : '<tr><td colspan="4" class="text-muted text-center p-3">연결 없음</td></tr>';
    }

    const lt = document.getElementById('net-listen-tbody');
    if (lt) {
      const ls = d.listening || [];
      lt.innerHTML = ls.length
        ? ls.map(l => `
          <tr>
            <td class="small font-monospace text-warning">${l.port}</td>
            <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(l.addr)}</td>
            <td class="small" style="color:#e6edf3">${escapeHtml(l.proc || '?')}</td>
          </tr>`).join('')
        : '<tr><td colspan="3" class="text-muted text-center p-3">없음</td></tr>';
    }

    renderNetEvents(d.events || []);
    drawNetTopology(d);
  }

  // NMS 스타일 네트워크 토폴로지 (SVG) — 중앙 호스트 + 방사형 피어 연결
  function drawNetTopology(d) {
    const svg = document.getElementById('net-topology');
    if (!svg) return;
    const W = svg.clientWidth || 520, H = 360, cx = W / 2, cy = H / 2;
    const conns = d.connections || [];
    const listening = d.listening || [];
    const events = d.events || [];
    const badIps = new Set(events.filter(e => e.kind === 'MALICIOUS_CONN').map(e => (e.details || {}).rip).filter(Boolean));

    // 원격 피어 집계 (IP별)
    const peers = {};
    conns.forEach(c => {
      if (!c.rip || c.rip === '-') return;
      if (!peers[c.rip]) peers[c.rip] = { ip: c.rip, external: c.external, count: 0, procs: new Set() };
      peers[c.rip].count++;
      if (c.proc) peers[c.rip].procs.add(c.proc);
    });
    const peerList = Object.values(peers).slice(0, 14);

    const colorOf = p => badIps.has(p.ip) ? '#f85149' : (p.external ? '#f0a500' : '#3fb950');
    const R = Math.min(cx, cy) - 62;
    let edges = '', nodes = '';

    peerList.forEach((p, i) => {
      const ang = (2 * Math.PI * i) / Math.max(1, peerList.length) - Math.PI / 2;
      const x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang);
      const col = colorOf(p), bad = badIps.has(p.ip);
      edges += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${col}" stroke-width="${bad ? 2.5 : 1.3}" stroke-opacity="${bad ? 0.9 : 0.45}" ${bad ? 'stroke-dasharray="4 3"' : ''}/>`;
      const r = 7 + Math.min(6, p.count);
      nodes += `<g>
        <circle cx="${x}" cy="${y}" r="${r}" fill="#0d1117" stroke="${col}" stroke-width="2"/>
        ${bad ? `<circle cx="${x}" cy="${y}" r="${r + 4}" fill="none" stroke="${col}" stroke-width="1" stroke-opacity="0.5"><animate attributeName="r" from="${r + 2}" to="${r + 9}" dur="1.2s" repeatCount="indefinite"/><animate attributeName="stroke-opacity" from="0.6" to="0" dur="1.2s" repeatCount="indefinite"/></circle>` : ''}
        <text x="${x}" y="${y - r - 5}" text-anchor="middle" font-size="10" font-family="monospace" fill="${col}">${escapeHtml(p.ip)}</text>
        <text x="${x}" y="${y + r + 12}" text-anchor="middle" font-size="9" fill="#8b949e">${[...p.procs][0] || ''} ×${p.count}</text>
      </g>`;
    });

    // 중앙 호스트 + 오픈 포트 링
    const portRing = listening.slice(0, 10).map((l, i) => {
      const ang = (2 * Math.PI * i) / Math.max(1, Math.min(10, listening.length));
      const x = cx + 34 * Math.cos(ang), y = cy + 34 * Math.sin(ang);
      const risky = ![22, 80, 443, 5055].includes(l.port);
      return `<circle cx="${x}" cy="${y}" r="3.5" fill="${risky ? '#f85149' : '#39d0d8'}"/>
        <text x="${x}" y="${y - 6}" text-anchor="middle" font-size="8" fill="${risky ? '#f85149' : '#8b949e'}">${l.port}</text>`;
    }).join('');

    const host = `<g>
      <circle cx="${cx}" cy="${cy}" r="26" fill="#161b22" stroke="var(--cyan,#39d0d8)" stroke-width="2.5"/>
      <text x="${cx}" y="${cy - 1}" text-anchor="middle" font-family="Font Awesome 6 Free" font-weight="900" font-size="18" fill="#39d0d8">&#xf233;</text>
      <text x="${cx}" y="${cy + 42}" text-anchor="middle" font-size="11" font-weight="700" fill="#e6edf3">홈서버</text>
    </g>`;

    const empty = peerList.length === 0 ? `<text x="${cx}" y="${cy + 70}" text-anchor="middle" font-size="11" fill="#8b949e">활성 외부 연결 없음</text>` : '';
    svg.innerHTML = edges + portRing + nodes + host + empty;
  }

  function renderNetTargets(targets) {
    const box = document.getElementById('net-targets');
    if (!box) return;
    box.innerHTML = targets.length
      ? targets.map(t => `
        <div class="p-2 border rounded" style="border-color:${t.up ? 'var(--green)' : 'var(--red)'}!important; min-width:160px; background:rgba(${t.up ? '63,185,80' : '248,81,73'},.08)">
          <div class="small" style="color:#e6edf3;font-weight:600">
            <i class="fa fa-circle me-1" style="font-size:8px;color:${t.up ? 'var(--green)' : 'var(--red)'}"></i>${escapeHtml(t.name)}</div>
          <div class="small font-monospace text-muted">${escapeHtml(t.host)}:${t.port}</div>
          <div class="small" style="color:${t.up ? 'var(--green)' : 'var(--red)'}">${t.up ? 'UP · ' + (t.latency_ms ?? '?') + 'ms' : 'DOWN'}</div>
        </div>`).join('')
      : '<div class="text-muted">감시 대상 없음</div>';
  }

  function renderNetEvents(events) {
    const box = document.getElementById('net-events');
    if (!box) return;
    box.innerHTML = events.length
      ? events.map(e => `
        <div class="p-1 border-bottom border-secondary small">
          <span class="badge" style="background:${sevColor(e.severity)};font-size:9px">${escapeHtml(e.severity)}</span>
          <span style="color:#e6edf3" class="ms-1">${escapeHtml(e.description)}</span>${demoBadge(e.details)}
          <div class="text-muted" style="font-size:10px">${escapeHtml(e.timestamp)}</div>
        </div>`).join('')
      : '<div class="text-muted p-2">이벤트 없음</div>';
  }

  socket.on('net_event', e => {
    const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
    if (e.kind === 'MALICIOUS_CONN') bump('net-malicious', 1);
    const badge = document.getElementById('sidebar-net-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
    pushLive('net', (e.severity || 'medium').toLowerCase(), `<b>네트워크</b> ${escapeHtml(e.description)}${demoBadge(e.details)}`);
    if (!document.getElementById('panel-network')?.classList.contains('d-none')) loadNetwork();
  });

  socket.on('net_status', s => {
    if (document.getElementById('panel-network')?.classList.contains('d-none')) return;
    const stats = s.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('net-established', stats.established);
    set('net-bandwidth', Math.round((stats.down_bps || 0) / 1024));
    renderNetTargets(s.targets || []);
  });

  /* ════════════════════ 퍼플팀 검증 ════════════════════ */
  let purpleScenarios = [];

  function loadPurple() {
    fetch('/api/purple/status').then(r => r.json()).then(renderPurple).catch(() => {});
  }

  function runPurpleAll() {
    const btnRow = document.getElementById('purple-tbody');
    if (btnRow) btnRow.innerHTML = '<tr><td colspan="6" class="text-center p-3 text-purple"><i class="fa fa-spinner fa-spin me-2"></i>모의 공격 주입 & 탐지 검증 중...</td></tr>';
    fetch('/api/purple/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario: 'all' }) })
      .then(r => r.json()).then(() => loadPurple()).catch(() => {});
  }

  function runPurpleOne(sid) {
    fetch('/api/purple/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario: sid }) })
      .then(r => r.json()).then(() => loadPurple()).catch(() => {});
  }

  function renderPurple(d) {
    const stats = d.stats || {};
    purpleScenarios = d.scenarios || [];
    const passed = purpleScenarios.filter(s => s.result && s.result.detected).length;
    const ran = purpleScenarios.filter(s => s.result).length;
    const failed = ran - passed;
    const cov = stats.last_coverage;

    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('purple-coverage', cov == null ? '-' : cov + '%');
    set('purple-passed', ran ? passed : '-');
    set('purple-failed', ran ? failed : '-');
    set('purple-runs', (stats.runs || 0).toLocaleString());

    const badge = document.getElementById('purple-cov-badge');
    if (badge) {
      badge.textContent = '커버리지 ' + (cov == null ? '-' : cov + '%');
      const c = cov == null ? '#30363d' : (cov >= 90 ? 'var(--green)' : cov >= 60 ? 'var(--orange)' : 'var(--red)');
      badge.style.background = c;
      badge.style.color = (cov != null && cov >= 90) ? '#001417' : '#e6edf3';
    }
    const sb = document.getElementById('sidebar-purple-cov');
    if (sb) sb.textContent = cov == null ? '-' : cov + '%';

    const tb = document.getElementById('purple-tbody');
    if (tb) {
      tb.innerHTML = purpleScenarios.map(s => {
        const r = s.result;
        const verdict = !r ? '<span class="badge bg-secondary" style="font-size:10px">미실행</span>'
          : (r.detected ? '<span class="badge bg-success" style="font-size:10px">PASS</span>'
                        : '<span class="badge bg-danger" style="font-size:10px">FAIL</span>');
        return `<tr style="${r && !r.detected ? 'background:rgba(248,81,73,.08)' : ''}">
          <td>${verdict}</td>
          <td class="small" style="color:#e6edf3">${escapeHtml(s.name)}</td>
          <td><span class="badge bg-dark" style="font-size:9px">${escapeHtml(s.mitre)}</span></td>
          <td class="small text-muted">${escapeHtml(s.expect)}</td>
          <td class="small" style="color:#e6edf3">${r ? escapeHtml(r.detail) : '-'}</td>
          <td><button class="btn btn-xs btn-outline-purple" onclick="runPurpleOne('${s.id}')" title="이 시나리오만 실행"><i class="fa fa-play"></i></button></td>
        </tr>`;
      }).join('');
    }
    drawPurpleFlow(passed, ran, cov);
  }

  // 공격 → 탐지 파이프라인 흐름 시각화 (SVG)
  function drawPurpleFlow(passed, ran, cov) {
    const svg = document.getElementById('purple-flow');
    if (!svg) return;
    const active = ran > 0;
    const okColor = cov != null && cov >= 90 ? '#3fb950' : (cov >= 60 ? '#f0a500' : '#f85149');
    const stages = [
      { icon: '', label: '모의 공격', sub: ran ? ran + '개 시나리오' : '대기', color: '#9d79f2' },
      { icon: '', label: '탐지 엔진', sub: 'Sigma·EDR·평판', color: active ? okColor : '#30363d' },
      { icon: '', label: 'AI 트리아지', sub: '정탐/오탐', color: active ? '#58a6ff' : '#30363d' },
      { icon: '', label: 'SOAR 대응', sub: '차단/종결', color: active ? '#39d0d8' : '#30363d' },
      { icon: '', label: '알림/인시던트', sub: '폰 푸시', color: active ? '#f0a500' : '#30363d' },
    ];
    const W = svg.clientWidth || 720, n = stages.length;
    const boxW = 118, gap = (W - boxW * n) / (n - 1), y = 30, h = 74;
    let parts = '';
    stages.forEach((s, i) => {
      const x = i * (boxW + gap);
      if (i < n - 1) {
        const ax = x + boxW, ax2 = x + boxW + gap;
        parts += `<line x1="${ax}" y1="${y + h / 2}" x2="${ax2}" y2="${y + h / 2}" stroke="${active ? okColor : '#30363d'}" stroke-width="2.5" marker-end="url(#pt-arrow)"/>`;
      }
      parts += `<g>
        <rect x="${x}" y="${y}" width="${boxW}" height="${h}" rx="9" fill="#0d1117" stroke="${s.color}" stroke-width="2"/>
        <text x="${x + boxW / 2}" y="${y + 26}" text-anchor="middle" font-family="Font Awesome 6 Free" font-weight="900" font-size="18" fill="${s.color}">${s.icon}</text>
        <text x="${x + boxW / 2}" y="${y + 46}" text-anchor="middle" font-size="12" font-weight="700" fill="#e6edf3">${s.label}</text>
        <text x="${x + boxW / 2}" y="${y + 62}" text-anchor="middle" font-size="10" fill="#8b949e">${s.sub}</text>
      </g>`;
    });
    const covText = cov == null ? '' :
      `<text x="${W / 2}" y="18" text-anchor="middle" font-size="12" font-weight="700" fill="${okColor}">탐지 커버리지 ${cov}% (${passed}/${ran} PASS)</text>`;
    svg.innerHTML = `<defs><marker id="pt-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L6,3 L0,6 Z" fill="${active ? okColor : '#30363d'}"/></marker></defs>${covText}${parts}`;
  }

  socket.on('purple_run', () => {
    if (!document.getElementById('panel-purple')?.classList.contains('d-none')) loadPurple();
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    checkReputation, edrKill, loadAuthlog, loadEdr, loadNetwork, loadPurple, loadReputation,
    loadSiem, renderAuthEvents, renderSiemEvents, runPurpleAll, runPurpleOne, sevColor,
    siemSetSearch,
  });
})();
