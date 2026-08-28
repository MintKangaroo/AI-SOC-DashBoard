/* dashboard/07-ops.js — 일일리포트·Sigma·패치·취약점스캔·웹퍼징·푸시알림
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
(function () {
  /* ════════════════════ 일일 AI 리포트 ════════════════════ */
  function loadReport() {
    fetch('/api/report/status').then(r => r.json()).then(renderReportPanel).catch(() => {});
  }

  function reportKpiCards(hl) {
    const card = (label, val, color) =>
      `<div class="col-4 col-md-3"><div class="stat-card stat-sm" style="border-left:3px solid ${color}">
        <div class="stat-value" style="color:${color}">${(val ?? 0).toLocaleString()}</div>
        <div class="stat-label">${label}</div></div></div>`;
    return [
      card('총 알림', hl.alerts_total, 'var(--cyan)'),
      card('정탐', hl.true_positives, 'var(--orange)'),
      card('오탐', hl.false_positives, 'var(--green)'),
      card('오탐율 %', hl.fp_rate, '#8b949e'),
      card('자동 차단', hl.auto_blocked, 'var(--red)'),
      card('EDR', hl.edr_detections, 'var(--info,#58a6ff)'),
      card('Sigma', hl.sigma_matches, 'var(--purple)'),
      card('브루트포스', hl.brute_alerts, 'var(--orange)'),
    ].join('');
  }

  function showReport(rep) {
    if (!rep) return;
    const t = document.getElementById('report-title');
    if (t) t.textContent = `리포트 ${rep.id}`;
    const g = document.getElementById('report-generated');
    if (g) g.textContent = rep.generated + (rep.ai_mode === 'claude' ? ' · Claude' : ' · 규칙기반');
    const k = document.getElementById('report-kpis');
    if (k) k.innerHTML = reportKpiCards(rep.highlights || {});
    const b = document.getElementById('report-briefing');
    if (b) b.textContent = rep.briefing || '(브리핑 없음)';
  }

  function renderReportPanel(d) {
    const stats = d.stats || {};
    const badge = document.getElementById('report-mode-badge');
    if (badge) {
      const claude = stats.ai_mode === 'claude';
      badge.textContent = claude ? 'Claude 브리핑' : '규칙 기반 (API 키 없음)';
      badge.style.background = claude ? 'var(--green)' : '#30363d';
      badge.style.color = claude ? '#001417' : '#e6edf3';
    }
    const note = document.getElementById('report-mode-note');
    if (note) note.textContent = stats.ai_mode === 'claude' ? '' : '(ANTHROPIC_API_KEY 설정 시 Claude가 작성)';

    const hist = document.getElementById('report-history');
    if (hist) {
      const hs = d.history || [];
      hist.innerHTML = hs.length
        ? hs.map(h => `
          <div class="p-2 border-bottom border-secondary small" style="cursor:pointer" onclick="openReport('${h.id}')">
            <div style="color:#e6edf3;font-weight:600"><i class="fa fa-file-lines me-1 text-cyan"></i>${escapeHtml(h.generated)}</div>
            <div class="text-muted" style="font-size:11px">
              알림 ${h.highlights?.alerts_total ?? 0} · 정탐 ${h.highlights?.true_positives ?? 0} · 오탐 ${h.highlights?.false_positives ?? 0}
              ${h.trigger === 'scheduled' ? '· <span class="text-info">예약</span>' : ''}</div>
          </div>`).join('')
        : '<div class="text-muted p-2">리포트 없음 — "지금 생성"을 눌러보세요</div>';
    }
    if (d.latest) showReport(d.latest);
  }

  function openReport(rid) {
    fetch('/api/report/' + rid).then(r => r.json()).then(showReport).catch(() => {});
  }

  function generateReport() {
    const b = document.getElementById('report-briefing');
    if (b) b.textContent = 'AI가 브리핑을 작성 중입니다...';
    fetch('/api/report/generate', { method: 'POST' }).then(r => r.json()).then(rep => {
      showReport(rep);
      loadReport();
    }).catch(() => { if (b) b.textContent = '생성 실패'; });
  }

  socket.on('daily_report', () => {
    if (!document.getElementById('panel-report')?.classList.contains('d-none')) loadReport();
  });

  /* ════════════════════ Sigma 룰 엔진 ════════════════════ */
  function loadSigma() {
    fetch('/api/integrations/sigma').then(r => r.json()).then(renderSigma).catch(() => {});
  }
  function reloadSigma() {
    fetch('/api/sigma/reload', { method: 'POST' }).then(r => r.json()).then(renderSigma).catch(() => {});
  }

  const SIGMA_LEVEL = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow,#d29922)', low: '#8b949e', informational: '#8b949e' };
  function sigmaLevelBadge(lv) {
    return `<span class="badge" style="background:${SIGMA_LEVEL[lv] || '#555'};font-size:9px;color:#fff">${escapeHtml(lv || '?')}</span>`;
  }

  let sigmaMatchBuffer = [];

  function renderSigma(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('sigma-rules', stats.rules_loaded);
    set('sigma-matches', stats.matches);
    set('sigma-evals', stats.evaluations);
    set('sigma-errors', stats.rules_error);

    const badge = document.getElementById('sigma-mode-badge');
    const note = document.getElementById('sigma-mode-note');
    if (badge) {
      const on = stats.enabled;
      badge.textContent = on ? `활성 · ${stats.rules_loaded}룰` : '비활성 (PyYAML 없음)';
      badge.style.background = on ? 'var(--green)' : '#30363d';
      badge.style.color = on ? '#001417' : '#e6edf3';
    }
    if (note) note.textContent = stats.enabled ? '' : '(PyYAML 미설치 — pip install pyyaml 후 재시작)';

    const rt = document.getElementById('sigma-rules-tbody');
    if (rt) {
      const rules = d.rules || [];
      rt.innerHTML = rules.length
        ? rules.map(r => `
          <tr style="opacity:${r.enabled ? 1 : 0.45}">
            <td>${sigmaLevelBadge(r.level)}</td>
            <td class="small" style="color:#e6edf3" title="${escapeHtml(r.id)}">${escapeHtml(r.title)}</td>
            <td class="small">${(r.mitre || []).map(m => `<span class="badge bg-dark" style="font-size:9px">${escapeHtml(m)}</span>`).join(' ') || '-'}</td>
            <td><div class="form-check form-switch mb-0">
              <input class="form-check-input" type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleSigma('${escapeHtml(r.id)}')">
            </div></td>
          </tr>`).join('')
        : '<tr><td colspan="4" class="text-muted text-center p-3">룰 없음</td></tr>';
    }

    sigmaMatchBuffer = d.matches || [];
    renderSigmaMatches();

    const lc = {};
    (d.rules || []).forEach(r => { lc[r.level] = (lc[r.level] || 0) + 1; });
    svgHBars('sigma-bars', [
      { label: 'critical', value: lc.critical || 0, color: '#f85149' },
      { label: 'high', value: lc.high || 0, color: '#f0a500' },
      { label: 'medium', value: lc.medium || 0, color: '#d29922' },
      { label: 'low', value: lc.low || 0, color: '#8b949e' },
    ], '개');
  }

  function sigmaMatchRow(m) {
    return `
      <tr style="background:rgba(248,81,73,${m.severity === 'CRITICAL' ? '.10' : '.05'})">
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((m.timestamp || '').slice(11))}</td>
        <td>${sigmaLevelBadge(m.level)}</td>
        <td class="small" style="color:#e6edf3">${escapeHtml(m.rule)}</td>
        <td class="small font-monospace text-truncate" style="max-width:260px;color:#e6edf3"
            title="${escapeHtml(m.cmdline || m.image || '')}">${escapeHtml(m.cmdline || m.image || '-')}</td>
        <td class="small">${(m.mitre || []).map(x => `<span class="badge bg-dark" style="font-size:9px">${escapeHtml(x)}</span>`).join(' ') || '-'}</td>
      </tr>`;
  }
  function renderSigmaMatches() {
    const tb = document.getElementById('sigma-matches-tbody');
    if (!tb) return;
    tb.innerHTML = sigmaMatchBuffer.length
      ? sigmaMatchBuffer.slice(0, 60).map(sigmaMatchRow).join('')
      : '<tr><td colspan="5" class="text-muted text-center p-3">매치 없음</td></tr>';
  }

  function toggleSigma(rid) {
    fetch('/api/sigma/toggle', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_id: rid })
    }).then(r => r.json()).then(() => loadSigma()).catch(() => {});
  }

  socket.on('sigma_match', m => {
    sigmaMatchBuffer.unshift(m);
    while (sigmaMatchBuffer.length > 300) sigmaMatchBuffer.pop();
    const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
    bump('sigma-matches', 1);
    const badge = document.getElementById('sidebar-sigma-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
    pushLive('sigma', (m.severity || 'medium').toLowerCase(),
      `<b>Sigma: ${escapeHtml(m.rule)}</b> ` +
      `<span class="font-monospace">${escapeHtml((m.cmdline || m.image || '').slice(0, 50))}</span>`);
    if (!document.getElementById('panel-sigma')?.classList.contains('d-none')) renderSigmaMatches();
  });

  /* ════════════════════ 취약점 패치 (Ansible) ════════════════════ */
  /* ══════════════ 취약점 스캔 (포트/서비스/CVE) ══════════════ */
  let _vulnHostsInit = false;
  let _vulnResults = {};      // host id -> result

  const VSEV = {
    critical: { c: '#ff3b6b', t: 'CRIT' }, high: { c: '#f85149', t: 'HIGH' },
    medium: { c: '#f79000', t: 'MED' }, low: { c: '#d29922', t: 'LOW' },
    info: { c: '#39d0d8', t: 'INFO' },
  };
  function vsevBadge(sev) {
    const s = VSEV[sev] || VSEV.info;
    return `<span class="badge" style="background:${s.c};color:#0d1117;font-size:9px;font-weight:700">${s.t}</span>`;
  }

  const VVERDICT = {
    vulnerable: { c: '#f85149', t: '미패치 · 정탐유력' },
    patched: { c: '#3fb950', t: '패치됨 · 오탐유력' },
    unknown: { c: '#6e7681', t: '미확인' },
  };
  function vulnVerdict(v) {
    if (!v) return '';
    const s = VVERDICT[v.state] || VVERDICT.unknown;
    const ver = v.installed
      ? `<span class="text-muted font-monospace" style="font-size:10px">설치: ${escapeHtml(v.installed)}${v.candidate ? ' → ' + escapeHtml(v.candidate) : ''}</span>` : '';
    return `<div class="mt-1"><span class="badge" style="background:${s.c};color:#0d1117;font-size:9px;font-weight:700"
      title="${escapeHtml(v.note || '')}">${s.t}</span> ${ver}
      <div class="small text-muted" style="font-size:10px">${escapeHtml(v.note || '')}</div></div>`;
  }

  function loadVulnScan() {
    fetch('/api/vulnscan/status').then(r => r.json()).then(renderVulnScan).catch(() => {});
  }

  function renderVulnScan(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('vuln-open', stats.open_ports);
    set('vuln-total', stats.vulns);
    set('vuln-high', (stats.high || 0) + (stats.critical || 0));
    set('vuln-hosts', stats.hosts);
    const sb = document.getElementById('sidebar-vuln-count');
    if (sb) sb.textContent = ((stats.high || 0) + (stats.critical || 0)).toLocaleString();

    const badge = document.getElementById('vuln-mode-badge');
    if (badge) {
      const real = stats.mode === 'real';
      badge.textContent = real ? '실측' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
      badge.style.background = real ? 'var(--green)' : '#30363d';
      badge.style.color = real ? '#001417' : '#e6edf3';
    }
    const eng = document.getElementById('vuln-engine-badge');
    if (eng) {
      eng.textContent = stats.nmap ? 'nmap' : 'socket 스캔';
      eng.style.background = stats.nmap ? 'var(--purple)' : '#30363d';
      eng.style.color = stats.nmap ? '#0d1117' : '#e6edf3';
    }
    const note = document.getElementById('vuln-mode-note');
    if (note) note.textContent = '(응답하는 대상은 실측 스캔 · 응답 없는 대상만 데모 샘플)';

    setVulnScanning(stats.scanning);
    renderVulnHosts(d.hosts || []);

    _vulnResults = {};
    (d.results || []).forEach(r => { _vulnResults[r.id] = r; });
    renderVulnResults();
    renderVulnHistory(d.history || []);
  }

  function setVulnScanning(on) {
    const btn = document.getElementById('vuln-scan-btn');
    const st = document.getElementById('vuln-scan-status');
    if (btn) btn.disabled = !!on;
    if (st) st.innerHTML = on
      ? '<i class="fa fa-spinner fa-spin me-1"></i>스캔 중...'
      : '';
  }

  function renderVulnHosts(hosts) {
    const box = document.getElementById('vuln-hosts-list');
    if (!box) return;
    const prev = vulnSelectedHosts();
    box.innerHTML = hosts.map(h => {
      const checked = _vulnHostsInit ? (prev.includes(h.id) ? 'checked' : '') : 'checked';
      const remote = h.conn === 'ssh';
      return `<label class="d-flex align-items-center gap-1 small" style="color:#e6edf3">
        <input type="checkbox" class="vuln-host" value="${escapeHtml(h.id)}" ${checked}>
        <i class="fa ${remote ? 'fa-network-wired text-orange' : 'fa-desktop text-cyan'}" style="font-size:11px"></i>
        ${escapeHtml(h.name)}<span class="text-muted font-monospace" style="font-size:10px">(${escapeHtml(h.addr)})</span>
      </label>`;
    }).join('') || '<span class="text-muted small">호스트 없음</span>';
    _vulnHostsInit = true;
  }

  function vulnSelectedHosts() {
    return Array.from(document.querySelectorAll('.vuln-host:checked')).map(c => c.value);
  }
  function vulnSelectAllHosts(on) {
    document.querySelectorAll('.vuln-host').forEach(c => { c.checked = on; });
  }

  function vulnScan() {
    const hosts = vulnSelectedHosts();
    if (!hosts.length) { alert('스캔할 서버를 하나 이상 선택하세요.'); return; }
    setVulnScanning(true);
    fetch('/api/vulnscan/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hosts }),
    }).then(r => r.json()).then(res => {
      if (res.status === 'busy') { setVulnScanning(false); alert(res.msg || '이미 스캔 중입니다.'); }
    }).catch(() => setVulnScanning(false));
  }

  function renderVulnResults() {
    const box = document.getElementById('vuln-results');
    if (!box) return;
    const list = Object.values(_vulnResults);
    if (!list.length) {
      box.innerHTML = '<div class="text-muted p-3 text-center">아직 스캔하지 않았습니다. 대상 선택 후 <strong>스캔</strong>을 누르세요.</div>';
      updateVulnSevChart();
      return;
    }
    box.innerHTML = list.map(r => {
      const rows = (r.ports || []).map(p => {
        const items = (p.cves || []).map(c =>
          `<div class="small">${vsevBadge(c.severity)} <span class="font-monospace text-danger">${escapeHtml(c.cve)}</span>
            <span class="text-muted">${escapeHtml(c.desc || '')}</span></div>`).join('')
          + (p.findings || []).map(f =>
          `<div class="small">${vsevBadge(f.severity)} <span class="text-orange">노출</span>
            <span class="text-muted">${escapeHtml(f.desc || '')}</span></div>`).join('');
        const demo = p.demo ? '<span class="demo-badge ms-1">데모</span>' : '';
        return `<tr>
          <td class="font-monospace text-cyan" style="white-space:nowrap">${p.port}</td>
          <td class="small" style="color:#e6edf3">${escapeHtml(p.service || '')}</td>
          <td class="small text-muted font-monospace text-truncate" style="max-width:180px" title="${escapeHtml(p.version || '')}">${escapeHtml(p.version || '—')}</td>
          <td>${vsevBadge(p.severity)}${demo}${vulnVerdict(p.verdict)}<div class="mt-1">${items || '<span class="small text-muted">알려진 취약점 없음</span>'}</div></td>
        </tr>`;
      }).join('');
      const remote = r.addr && r.addr !== '127.0.0.1';
      return `<div class="mb-3">
        <div class="d-flex align-items-center gap-2 mb-1">
          <i class="fa ${remote ? 'fa-network-wired text-orange' : 'fa-desktop text-cyan'}"></i>
          <strong style="color:#e6edf3">${escapeHtml(r.host)}</strong>
          <span class="text-muted font-monospace small">${escapeHtml(r.addr)}</span>
          <span class="badge bg-secondary ms-1" style="font-size:10px">열린 포트 ${r.open || 0}</span>
          <span class="badge bg-danger" style="font-size:10px">취약점 ${r.vulns || 0}</span>
          <span class="text-muted small ms-auto">${escapeHtml(r.scanned || '')}</span>
        </div>
        <div class="table-responsive">
          <table class="table table-dark table-sm mb-0" style="font-size:12px">
            <thead><tr><th style="width:60px">포트</th><th style="width:90px">서비스</th><th>버전</th><th>취약점 / 노출</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="4" class="text-muted text-center p-2">열린 포트 없음</td></tr>'}</tbody>
          </table>
        </div>
      </div>`;
    }).join('');
    updateVulnSevChart();
  }

  function updateVulnSevChart() {
    const cnt = { critical: 0, high: 0, medium: 0, low: 0 };
    Object.values(_vulnResults).forEach(r => (r.ports || []).forEach(p => {
      [...(p.cves || []), ...(p.findings || [])].forEach(x => {
        if (cnt[x.severity] !== undefined) cnt[x.severity]++;
      });
    }));
    svgHBars('vuln-sev-bars', [
      { label: 'Critical', value: cnt.critical, color: VSEV.critical.c },
      { label: 'High', value: cnt.high, color: VSEV.high.c },
      { label: 'Medium', value: cnt.medium, color: VSEV.medium.c },
      { label: 'Low', value: cnt.low, color: VSEV.low.c },
    ]);
  }

  function renderVulnHistory(hist) {
    const box = document.getElementById('vuln-history');
    if (!box) return;
    box.innerHTML = hist.length
      ? hist.map(h => `<div class="p-1 border-bottom border-secondary small" style="color:#e6edf3">
          <i class="fa fa-radar text-cyan me-1"></i>${escapeHtml(h.ts)}
          <span class="text-muted ms-1">서버 ${h.hosts} · 포트 ${h.open_ports} · 취약 ${h.vulns}</span></div>`).join('')
      : '<div class="text-muted p-2">이력 없음</div>';
  }

  socket.on('vulnscan_host', res => {
    _vulnResults[res.id] = res;
    renderVulnResults();
  });
  socket.on('vulnscan_status', d => {
    const stats = (d && d.stats) || {};
    setVulnScanning(stats.scanning);
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('vuln-open', stats.open_ports);
    set('vuln-total', stats.vulns);
    set('vuln-high', (stats.high || 0) + (stats.critical || 0));
    const sb = document.getElementById('sidebar-vuln-count');
    if (sb) sb.textContent = ((stats.high || 0) + (stats.critical || 0)).toLocaleString();
  });

  /* ══════════════ 웹 퍼징 (견고성) ══════════════ */
  const FTYPE = {
    server_error: { c: '#f85149', t: '5xx' }, timeout: { c: '#f79000', t: '응답없음' },
    reflection: { c: '#a371f7', t: '입력반사' }, latency: { c: '#d29922', t: '지연' },
  };
  let _fuzzTargetsInit = false;

  function loadFuzz() {
    fetch('/api/fuzz/status').then(r => r.json()).then(renderFuzz).catch(() => {});
  }

  function renderFuzz(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('fuzz-requests', stats.requests);
    set('fuzz-5xx', stats.errors_5xx);
    set('fuzz-timeouts', stats.timeouts);
    set('fuzz-reflections', stats.reflections);
    const sb = document.getElementById('sidebar-fuzz-count');
    if (sb) sb.textContent = (stats.findings || 0).toLocaleString();

    const eng = document.getElementById('fuzz-engine-badge');
    if (eng) { eng.textContent = stats.engine || '-'; eng.style.background = 'var(--purple)'; eng.style.color = '#0d1117'; }
    const rn = document.getElementById('fuzz-rate-note');
    const pc = document.getElementById('fuzz-payload-count');
    if (pc) pc.textContent = d.payload_count ?? '-';
    const mn = document.getElementById('fuzz-mode-note');
    if (mn) mn.textContent = stats.allow_write ? '(POST 허용됨)' : '(GET 전용 잠금)';

    // 대상 select — 최초 1회 채움(공인 IP는 비활성)
    const sel = document.getElementById('fuzz-target');
    if (sel && !_fuzzTargetsInit) {
      sel.innerHTML = (d.targets || []).map(t =>
        `<option value="${escapeHtml(t.id)}" ${t.private ? '' : 'disabled'}>
          ${escapeHtml(t.name)} — ${escapeHtml(t.base)}${t.private ? '' : ' (공인 IP 불가)'}</option>`).join('');
      _fuzzTargetsInit = true;
    }
    if (rn) rn.textContent = 'rate limit';

    setFuzzing(stats.fuzzing);
    renderFuzzFindings(d.findings || []);
    renderFuzzHistory(d.history || []);
  }

  function setFuzzing(on) {
    const btn = document.getElementById('fuzz-run-btn');
    const st = document.getElementById('fuzz-run-status');
    if (btn) btn.disabled = !!on;
    if (st) st.innerHTML = on ? '<i class="fa fa-spinner fa-spin me-1"></i>퍼징 중...' : '';
  }

  function fuzzRun() {
    const target = document.getElementById('fuzz-target').value;
    const paths = document.getElementById('fuzz-paths').value.split(',').map(s => s.trim()).filter(Boolean);
    const params = document.getElementById('fuzz-params').value.split(',').map(s => s.trim()).filter(Boolean);
    const method = document.getElementById('fuzz-method').value;
    if (method === 'POST' && !confirm('POST(쓰기) 퍼징은 서버 상태를 바꿀 수 있습니다. 계속할까요?')) return;
    setFuzzing(true);
    fetch('/api/fuzz/run', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, paths, params, method }),
    }).then(r => r.json()).then(res => {
      if (res.status !== 'started') { setFuzzing(false); alert(res.msg || res.status); }
    }).catch(() => setFuzzing(false));
  }

  function fuzzStop() {
    fetch('/api/fuzz/stop', { method: 'POST' }).catch(() => {});
  }

  let _fuzzFindings = [];
  function renderFuzzFindings(list) {
    _fuzzFindings = list.slice();
    drawFuzzFindings();
  }
  function drawFuzzFindings() {
    const tb = document.getElementById('fuzz-findings-tbody');
    if (!tb) return;
    tb.innerHTML = _fuzzFindings.length
      ? _fuzzFindings.map(f => {
        const ty = FTYPE[f.type] || { c: '#6e7681', t: f.type };
        return `<tr>
          <td class="small text-muted font-monospace">${escapeHtml(f.time || '')}</td>
          <td>${vsevBadge(f.severity)} <span class="small" style="color:${ty.c}">${escapeHtml(ty.t)}</span></td>
          <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(f.path || '')}<span class="text-muted">?${escapeHtml(f.param || '')}</span></td>
          <td class="small"><span class="badge bg-secondary" style="font-size:9px">${escapeHtml(f.payload_label || '')}</span>
            <div class="text-muted font-monospace text-truncate" style="max-width:150px" title="${escapeHtml(f.payload || '')}">${escapeHtml(f.payload || '')}</div></td>
          <td class="small font-monospace" style="color:#e6edf3">${f.status ?? '—'}<div class="text-muted" style="font-size:10px">${f.elapsed_ms ?? 0}ms</div></td>
          <td class="small text-muted">${escapeHtml(f.desc || '')}</td>
        </tr>`;
      }).join('')
      : '<tr><td colspan="6" class="text-muted text-center p-3">발견 없음 — 서버가 입력을 안전하게 처리 중</td></tr>';

    const cnt = { server_error: 0, timeout: 0, reflection: 0, latency: 0 };
    _fuzzFindings.forEach(f => { if (cnt[f.type] !== undefined) cnt[f.type]++; });
    svgHBars('fuzz-type-bars', [
      { label: '5xx/미처리', value: cnt.server_error, color: FTYPE.server_error.c },
      { label: '응답없음', value: cnt.timeout, color: FTYPE.timeout.c },
      { label: '입력반사', value: cnt.reflection, color: FTYPE.reflection.c },
      { label: '지연', value: cnt.latency, color: FTYPE.latency.c },
    ]);
  }

  function renderFuzzHistory(hist) {
    const box = document.getElementById('fuzz-history');
    if (!box) return;
    box.innerHTML = hist.length
      ? hist.map(h => `<div class="p-1 border-bottom border-secondary small" style="color:#e6edf3">
          <i class="fa fa-bug text-danger me-1"></i>${escapeHtml(h.ts)}
          <div class="text-muted" style="font-size:10.5px">${escapeHtml(h.target)} · ${escapeHtml(h.method)} · 요청 ${h.requests} · 발견 ${h.findings}${h.stopped ? ' · 중단됨' : ''}</div></div>`).join('')
      : '<div class="text-muted p-2">이력 없음</div>';
  }

  socket.on('fuzz_finding', f => {
    _fuzzFindings.unshift(f);
    if (_fuzzFindings.length > 80) _fuzzFindings.pop();
    drawFuzzFindings();
  });
  socket.on('fuzz_status', d => {
    const stats = (d && d.stats) || {};
    setFuzzing(stats.fuzzing);
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('fuzz-requests', stats.requests);
    set('fuzz-5xx', stats.errors_5xx);
    set('fuzz-timeouts', stats.timeouts);
    set('fuzz-reflections', stats.reflections);
    const sb = document.getElementById('sidebar-fuzz-count');
    if (sb) sb.textContent = (stats.findings || 0).toLocaleString();
    if (!stats.fuzzing) setTimeout(loadFuzz, 300);   // 종료 후 이력/발견 최종 동기화
  });

  function loadPatch(rescan) {
    const url = rescan ? '/api/patch/scan' : '/api/patch/status';
    fetch(url, rescan ? { method: 'POST' } : {}).then(r => r.json()).then(renderPatch).catch(() => {});
  }

  function renderPatch(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('patch-upgradable', stats.upgradable);
    set('patch-security', stats.security);
    set('patch-jobs', stats.jobs_run);
    const ansEl = document.getElementById('patch-ansible');
    if (ansEl) ansEl.textContent = stats.ansible ? '있음' : '미설치';
    const badge = document.getElementById('patch-mode-badge');
    const note = document.getElementById('patch-mode-note');
    if (badge) {
      const real = stats.mode === 'real';
      badge.textContent = real ? '실측 (apt)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
      badge.style.background = real ? 'var(--green)' : '#30363d';
      badge.style.color = real ? '#001417' : '#e6edf3';
    }
    if (note) {
      const parts = [];
      if (stats.mode === 'demo') parts.push('데모 취약 패키지 표시 중 (실서버는 apt 실스캔)');
      parts.push(stats.apply_enabled ? '실제 적용 허용됨' : '실제 적용 잠금(dry-run만)');
      note.textContent = '(' + parts.join(' · ') + ')';
    }
    const sbadge = document.getElementById('sidebar-patch-count');
    if (sbadge) sbadge.textContent = (stats.security || 0).toLocaleString();

    const tb = document.getElementById('patch-inv-tbody');
    if (tb) {
      const inv = d.inventory || [];
      tb.innerHTML = inv.length
        ? inv.map(p => `
          <tr ${p.security ? 'style="background:rgba(248,81,73,.06)"' : ''}>
            <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(p.package)}
              ${p.cve ? `<span class="badge bg-danger ms-1" style="font-size:9px">${escapeHtml(p.cve)}</span>` : ''}</td>
            <td class="small text-muted"><span class="font-monospace">${escapeHtml(p.current)}</span> →
              <span class="font-monospace text-success">${escapeHtml(p.candidate)}</span></td>
            <td>${p.security ? '<span class="badge bg-danger" style="font-size:10px">보안</span>' : '<span class="badge bg-secondary" style="font-size:10px">일반</span>'}</td>
          </tr>`).join('')
        : '<tr><td colspan="3" class="text-muted text-center p-3">업데이트 없음 (최신)</td></tr>';
    }
    renderPatchHosts(d.hosts || []);
    renderPatchJobs(d.jobs || []);

    const up = stats.upgradable || 0, sec = stats.security || 0;
    svgDonut('patch-donut', [
      { label: '보안 패치', value: sec, color: '#f85149' },
      { label: '일반 업데이트', value: Math.max(0, up - sec), color: '#39d0d8' },
    ], up.toLocaleString(), '업그레이드 가능');
  }

  /* 대상 서버 체크박스 — 갱신 시 기존 선택 유지, 최초엔 localhost 기본 선택 */
  let _patchHostsInit = false;
  function renderPatchHosts(hosts) {
    const box = document.getElementById('patch-hosts');
    if (!box) return;
    const prev = patchSelectedHosts();          // 현재 선택 보존
    box.innerHTML = hosts.map(h => {
      const checked = _patchHostsInit
        ? (prev.includes(h.id) ? 'checked' : '')
        : (h.conn === 'local' ? 'checked' : '');   // 최초: localhost만
      const remote = h.conn === 'ssh';
      return `<label class="d-flex align-items-center gap-1 small" style="color:#e6edf3">
        <input type="checkbox" class="patch-host" value="${escapeHtml(h.id)}" ${checked}>
        <i class="fa ${remote ? 'fa-network-wired text-orange' : 'fa-desktop text-cyan'}" style="font-size:11px"></i>
        ${escapeHtml(h.name)}${remote ? `<span class="text-muted font-monospace" style="font-size:10px">(${escapeHtml(h.addr)})</span>` : ''}
      </label>`;
    }).join('') || '<span class="text-muted small">호스트 없음</span>';
    _patchHostsInit = true;
  }

  function patchSelectedHosts() {
    return Array.from(document.querySelectorAll('.patch-host:checked')).map(c => c.value);
  }

  function patchSelectAllHosts(on) {
    document.querySelectorAll('.patch-host').forEach(c => { c.checked = on; });
  }

  function renderPatchJobs(jobs) {
    const box = document.getElementById('patch-jobs-list');
    if (!box) return;
    const statusColor = { success: 'var(--green)', simulated: 'var(--cyan)', failed: 'var(--red)', blocked: 'var(--orange)', running: 'var(--yellow,#d29922)' };
    box.innerHTML = jobs.length
      ? jobs.map(j => `
        <div class="p-1 border-bottom border-secondary small" style="cursor:pointer" onclick='showPatchLog(${JSON.stringify(j).replace(/'/g, "&#39;")})'>
          <span class="badge" style="background:${statusColor[j.status] || '#555'};font-size:9px">${escapeHtml(j.status)}</span>
          <span style="color:#e6edf3" class="ms-1">#${j.id} ${j.kind === 'command'
            ? `<i class="fa fa-terminal me-1"></i><span class="font-monospace">${escapeHtml((j.command || '').slice(0, 32))}</span>`
            : `${j.mode === 'check' ? 'Dry-run' : j.mode} ${j.security_only ? '(보안만)' : '(전체)'}`}
            ${Array.isArray(j.hosts) && j.hosts.length ? `<span class="text-muted" style="font-size:9px">· ${escapeHtml(j.hosts.join(', '))}</span>` : ''}</span>
          <div class="text-muted" style="font-size:10px">${escapeHtml(j.result || '')}</div>
        </div>`).join('')
      : '<div class="text-muted p-2">작업 없음</div>';
  }

  function showPatchLog(job) {
    const out = document.getElementById('patch-output');
    if (!out) return;
    const head = job.kind === 'command'
      ? `# 작업 #${job.id} [${job.status}] 명령: ${job.command || ''}`
      : `# 작업 #${job.id} [${job.status}] ${job.result || ''}\n# 플레이북: ${job.playbook || ''}`;
    const hosts = Array.isArray(job.hosts) && job.hosts.length ? `\n# 대상: ${job.hosts.join(', ')}` : '';
    out.textContent = `${head}${hosts}\n\n${job.log || '(로그 없음)'}`;
  }

  function patchPlaybook() {
    fetch('/api/patch/playbook', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ security_only: true })
    }).then(r => r.json()).then(d => {
      const out = document.getElementById('patch-output');
      if (out) out.textContent = `# 생성됨: ${d.path}\n# 검토 후 실행: ansible-playbook -i localhost, -c local ${d.path}\n\n${d.content}`;
    }).catch(() => {});
  }

  function patchRun(mode) {
    const hosts = patchSelectedHosts();
    if (!hosts.length) { alert('대상 서버를 하나 이상 선택하세요.'); return; }
    const label = mode === 'apply' ? '일괄 실제 적용' : 'Dry-run(점검)';
    if (mode === 'apply' && !confirm(`선택한 ${hosts.length}대 서버에 실제 패치를 적용합니다.\n운영 중 자동매매 봇이 영향받을 수 있습니다. 점검 시간대인가요?\n(PATCH_APPLY_ENABLED=False면 자동 차단됩니다)`)) return;
    const out = document.getElementById('patch-output');
    if (out) out.textContent = `${label} 실행 중... (대상 ${hosts.length}대)`;
    fetch('/api/patch/run', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, security_only: true, hosts })
    }).then(r => r.json()).then(() => {
      setTimeout(() => loadPatch(), 1200);   // 작업 완료 후 이력/로그 갱신
    }).catch(() => { if (out) out.textContent = '실행 요청 실패'; });
  }

  function patchCommand(mode) {
    const hosts = patchSelectedHosts();
    if (!hosts.length) { alert('대상 서버를 하나 이상 선택하세요.'); return; }
    const input = document.getElementById('patch-cmd-input');
    const command = (input?.value || '').trim();
    if (!command) { alert('실행할 명령을 입력하세요.'); return; }
    if (mode === 'apply' && !confirm(`선택한 ${hosts.length}대 서버에서 명령을 실제 실행합니다:\n\n${command}\n\n(PATCH_APPLY_ENABLED=False면 차단, 파괴적 명령은 자동 차단)`)) return;
    const out = document.getElementById('patch-output');
    if (out) out.textContent = `${mode === 'apply' ? '명령 실행' : '미리보기'} 중... (대상 ${hosts.length}대)`;
    fetch('/api/patch/command', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command, mode, hosts })
    }).then(r => r.json()).then(() => {
      setTimeout(() => loadPatch(), 1000);
    }).catch(() => { if (out) out.textContent = '명령 요청 실패'; });
  }

  socket.on('patch_job', j => {
    if (document.getElementById('panel-patch')?.classList.contains('d-none')) return;
    loadPatch();
    showPatchLog(j);
  });

  /* ════════════════════ 푸시 알림 (ntfy) ════════════════════ */
  function loadNotify() {
    fetch('/api/notify/status').then(r => r.json()).then(renderNotify).catch(() => {});
  }

  function renderNotify(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('notify-sent', stats.sent);
    set('notify-suppressed', stats.suppressed);
    set('notify-failed', stats.failed);
    const srvEl = document.getElementById('notify-server');
    if (srvEl) srvEl.textContent = (d.server || '-').replace(/^https?:\/\//, '');
    const minEl = document.getElementById('notify-minsev');
    if (minEl) minEl.textContent = d.min_severity || 'CRITICAL';

    const badge = document.getElementById('notify-mode-badge');
    const note = document.getElementById('notify-mode-note');
    if (badge) {
      badge.textContent = d.active ? '활성 (폰 연결됨)' : '비활성 (미설정)';
      badge.style.background = d.active ? 'var(--green)' : '#30363d';
      badge.style.color = d.active ? '#001417' : '#e6edf3';
    }
    if (note) note.textContent = d.active ? '' : '(NTFY_ENABLED=True + NTFY_TOPIC 설정 후 재시작하면 폰으로 알림)';

    const tb = document.getElementById('notify-hist-tbody');
    if (tb) {
      const h = d.history || [];
      tb.innerHTML = h.length
        ? h.map(e => `
          <tr>
            <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((e.timestamp || '').slice(11))}</td>
            <td><span class="badge" style="background:${sevColor(e.severity)};font-size:9px">${escapeHtml(e.severity)}</span></td>
            <td class="small" style="color:#e6edf3">${escapeHtml(e.title)}</td>
            <td class="small">${e.delivered ? '<span class="text-success">전송✓</span>' : `<span class="text-muted">${escapeHtml(e.detail || '미전송')}</span>`}</td>
          </tr>`).join('')
        : '<tr><td colspan="4" class="text-muted text-center p-3">이력 없음</td></tr>';
    }

    svgHBars('notify-bars', [
      { label: '전송 성공', value: stats.sent || 0, color: '#3fb950' },
      { label: '쿨다운 억제', value: stats.suppressed || 0, color: '#f0a500' },
      { label: '실패', value: stats.failed || 0, color: '#f85149' },
    ], '건');
  }

  function notifyTest() {
    const res = document.getElementById('notify-test-result');
    if (res) { res.textContent = '전송 중...'; res.className = 'small ms-2 text-muted'; }
    fetch('/api/notify/test', { method: 'POST' }).then(r => r.json()).then(d => {
      if (!res) return;
      if (d.ok) { res.textContent = '✓ ' + d.detail; res.className = 'small ms-2 text-success'; }
      else { res.textContent = (d.active ? '실패: ' : '비활성 — .env 설정 필요: ') + d.detail; res.className = 'small ms-2 text-warning'; }
      loadNotify();
    }).catch(() => { if (res) res.textContent = '요청 실패'; });
  }

  socket.on('notify_event', e => {
    if (document.getElementById('panel-notify')?.classList.contains('d-none')) return;
    loadNotify();
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    fuzzRun, fuzzStop, generateReport, loadFuzz, loadNotify, loadPatch, loadReport,
    loadSigma, loadVulnScan, notifyTest, openReport, patchCommand, patchPlaybook, patchRun,
    patchSelectAllHosts, reloadSigma, showPatchLog, toggleSigma, vulnScan,
    vulnSelectAllHosts,
  });
})();
