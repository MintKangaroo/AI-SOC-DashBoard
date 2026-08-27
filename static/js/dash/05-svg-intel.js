/* dashboard/05-svg-intel.js — 재사용 SVG 헬퍼·위협 인텔리전스
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
/* ════════════════════ 재사용 SVG 차트 헬퍼 (외부 라이브러리 없음) ════════════════════ */
// 도넛 차트: segs = [{label, value, color}]
function svgDonut(elId, segs, centerTop, centerSub) {
  const svg = document.getElementById(elId);
  if (!svg) return;
  const W = svg.clientWidth || 260, H = svg.getAttribute('height') * 1 || 170;
  const cx = Math.min(90, W / 3), cy = H / 2, r = Math.min(cy - 12, 58), sw = 20;
  const total = segs.reduce((a, s) => a + (s.value || 0), 0);
  const C = 2 * Math.PI * r;
  let off = 0, ring = '';
  if (total > 0) {
    segs.forEach(s => {
      const frac = (s.value || 0) / total;
      if (frac <= 0) return;
      const len = frac * C;
      ring += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${sw}"
        stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 ${cx} ${cy})"/>`;
      off += len;
    });
  } else {
    ring = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#21262d" stroke-width="${sw}"/>`;
  }
  const center = `<text x="${cx}" y="${cy - 2}" text-anchor="middle" font-size="20" font-weight="800" fill="#e6edf3">${escapeHtml(centerTop ?? total)}</text>
    <text x="${cx}" y="${cy + 15}" text-anchor="middle" font-size="10" fill="#8b949e">${escapeHtml(centerSub || '')}</text>`;
  const lx = cx + r + sw + 6;
  let legend = '';
  segs.forEach((s, i) => {
    const ly = cy - segs.length * 11 + i * 22 + 6;
    const pct = total ? Math.round((s.value || 0) / total * 100) : 0;
    legend += `<rect x="${lx}" y="${ly - 9}" width="11" height="11" rx="2" fill="${s.color}"/>
      <text x="${lx + 17}" y="${ly}" font-size="11" fill="#c9d1d9">${escapeHtml(s.label)}</text>
      <text x="${lx + 17}" y="${ly + 13}" font-size="10" fill="#8b949e">${(s.value || 0).toLocaleString()} · ${pct}%</text>`;
  });
  svg.innerHTML = ring + center + legend;
}

// 가로 막대: items = [{label, value, color}]
function svgHBars(elId, items, unit) {
  const svg = document.getElementById(elId);
  if (!svg) return;
  const W = svg.clientWidth || 300;
  const rowH = 26, padL = 96, padR = 46, top = 6;
  const H = Math.max(40, top * 2 + items.length * rowH);
  svg.setAttribute('height', H);
  if (!items.length) {
    svg.innerHTML = `<text x="${W / 2}" y="26" text-anchor="middle" font-size="11" fill="#8b949e">데이터 없음</text>`;
    return;
  }
  const max = Math.max(1, ...items.map(i => i.value || 0));
  const barMax = W - padL - padR;
  let out = '';
  items.forEach((it, i) => {
    const y = top + i * rowH;
    const w = Math.max(2, (it.value || 0) / max * barMax);
    out += `<text x="${padL - 8}" y="${y + 15}" text-anchor="end" font-size="11" fill="#c9d1d9">${escapeHtml((it.label ?? '').toString().slice(0, 16))}</text>
      <rect x="${padL}" y="${y + 4}" width="${barMax}" height="15" rx="3" fill="#161b22"/>
      <rect x="${padL}" y="${y + 4}" width="${w}" height="15" rx="3" fill="${it.color || 'var(--cyan)'}"/>
      <text x="${padL + w + 6}" y="${y + 15}" font-size="11" font-weight="700" fill="#e6edf3">${(it.value || 0).toLocaleString()}${unit || ''}</text>`;
  });
  svg.innerHTML = out;
}

function updateMitreStats(data) {
  const total = data.total_mapped || 0;
  const unique = data.unique_techniques || 0;
  document.getElementById('mitre-total').textContent = total.toLocaleString();
  document.getElementById('mitre-unique').textContent = unique;

  const totalTechniques = (data.tactics || [])
    .reduce((a, t) => a + (t.techniques?.length || 0), 0);
  const coverage = totalTechniques
    ? ((unique / totalTechniques) * 100).toFixed(1)
    : 0;
  document.getElementById('mitre-coverage').textContent = coverage + '%';
}

function loadMitreTop() {
  fetch('/api/mitre/top?top=10')
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('mitre-top-list');
      if (!el) return;
      const top = d.top || [];
      if (!top.length) {
        el.innerHTML = '<div class="text-muted p-2">아직 탐지된 Technique 없음</div>';
        return;
      }
      const max = top[0].count;
      el.innerHTML = top.map((t, i) => {
        const pct = max ? (t.count / max * 100).toFixed(0) : 0;
        return `<div class="mitre-top-item">
          <span class="rank">#${i + 1}</span>
          <span class="tech-code font-monospace">${escapeHtml(t.technique_id)}</span>
          <span class="tech-name">${escapeHtml(t.ko)} <span class="text-muted">(${escapeHtml(t.tactic_name)})</span></span>
          <div class="bar-wrap"><div class="bar" style="width:${pct}%"></div></div>
          <span class="count">${t.count}</span>
        </div>`;
      }).join('');
    });
}

function loadMitreRecent() {
  fetch('/api/mitre/recent?limit=30')
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('mitre-recent-list');
      if (!el) return;
      const events = d.events || [];
      if (!events.length) {
        el.innerHTML = '<div class="text-muted p-2">최근 매핑된 이벤트 없음</div>';
        return;
      }
      el.innerHTML = events.map(e => {
        const sev = (e.severity || 'MEDIUM').toUpperCase();
        const sevCls = sev === 'CRITICAL' ? 'bg-danger'
                    : sev === 'HIGH'     ? 'bg-orange'
                    : 'bg-warning text-dark';
        return `
        <div class="mitre-recent-item" style="color:#e6edf3">
          <span class="ts" style="color:#e6edf3">${(e.timestamp||'').split(' ')[1] || e.timestamp}</span>
          <span class="badge bg-danger font-monospace">${escapeHtml(e.technique_id)}</span>
          <span class="badge ${sevCls}" style="font-size:9px">${sev}</span>
          <span class="tactic" style="color:#e6edf3">${escapeHtml(e.tactic_ko || e.tactic_id)}</span>
          <span class="desc" style="color:#e6edf3">${escapeHtml(e.description||'')}</span>
        </div>`;
      }).join('');
    });
}

socket.on('mitre_hit', entry => {
  // MITRE 매핑 KPI
  const kpiEl = document.getElementById('kpi-mitre');
  if (kpiEl) kpiEl.textContent = parseInt(kpiEl.textContent || 0) + 1;

  // 매트릭스 셀 카운트 즉시 업데이트
  const cell = document.querySelector(
    `.mitre-technique[data-tactic="${entry.tactic_id}"][data-technique="${entry.technique_id}"]`
  );
  if (cell) {
    let cntEl = cell.querySelector('.tech-count');
    const cur = cntEl ? parseInt(cntEl.textContent, 10) : 0;
    const next = cur + 1;
    if (!cntEl) {
      cntEl = document.createElement('div');
      cntEl.className = 'tech-count';
      cell.appendChild(cntEl);
    }
    cntEl.textContent = next;
    cell.classList.remove('hit-low', 'hit-med', 'hit-high');
    cell.classList.add(next >= 10 ? 'hit-high' : next >= 3 ? 'hit-med' : 'hit-low');
    cell.classList.add('hit-flash');
    setTimeout(() => cell.classList.remove('hit-flash'), 800);
  }

  // 총합 카운트 업데이트
  const totalEl = document.getElementById('mitre-total');
  if (totalEl) totalEl.textContent = (parseInt(totalEl.textContent.replace(/,/g, '')) + 1).toLocaleString();

  // 최근 이벤트 프리펜드
  const recentList = document.getElementById('mitre-recent-list');
  if (recentList && recentList.querySelector('.mitre-recent-item')) {
    const sev = (entry.severity || 'MEDIUM').toUpperCase();
    const sevCls = sev === 'CRITICAL' ? 'bg-danger'
                : sev === 'HIGH'     ? 'bg-orange'
                : 'bg-warning text-dark';
    const div = document.createElement('div');
    div.className = 'mitre-recent-item new';
    div.setAttribute('style', 'color:#e6edf3');
    div.innerHTML = `
      <span class="ts" style="color:#e6edf3">${(entry.timestamp||'').split(' ')[1] || entry.timestamp}</span>
      <span class="badge bg-danger font-monospace">${escapeHtml(entry.technique_id)}</span>
      <span class="badge ${sevCls}" style="font-size:9px">${sev}</span>
      <span class="tactic" style="color:#e6edf3">${escapeHtml(entry.tactic_ko || entry.tactic_id)}</span>
      <span class="desc" style="color:#e6edf3">${escapeHtml(entry.description||'')}</span>`;
    recentList.insertBefore(div, recentList.firstChild);
    while (recentList.children.length > 30) recentList.removeChild(recentList.lastChild);
  }

  // 상세 로그 테이블 프리펜드
  mitreLogBuffer.unshift(entry);
  while (mitreLogBuffer.length > MITRE_LOG_MAX) mitreLogBuffer.pop();
  const logTbody = document.getElementById('mitre-log-tbody');
  if (logTbody) {
    renderMitreLog();
    const firstRow = logTbody.querySelector('tr');
    if (firstRow) {
      firstRow.classList.add('row-flash');
      setTimeout(() => firstRow.classList.remove('row-flash'), 800);
    }
  }
});

/* ════════════════════ 위협 인텔리전스 ════════════════════ */
function loadThreatIntel() {
  fetch('/api/threat-intel/status')
    .then(r => r.json())
    .then(d => renderThreatIntel(d))
    .catch(() => {});
}

function renderThreatIntel(d) {
  const stats = d.stats || {};
  const setIf = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  setIf('ti-bad-ip',      (stats.bad_ip_count||0).toLocaleString());
  setIf('ti-bad-url',     (stats.bad_url_count||0).toLocaleString());
  setIf('ti-total-match', (stats.total_matches||0).toLocaleString());
  setIf('ti-last-refresh', stats.last_refresh || '-');
  setIf('ov-ti-bad-ip',   (stats.bad_ip_count||0).toLocaleString());
  setIf('ov-ti-bad-url',  (stats.bad_url_count||0).toLocaleString());
  setIf('ov-ti-match',    (stats.total_matches||0).toLocaleString());

  const srcTbody = document.getElementById('ti-sources-tbody');
  if (srcTbody) {
    const rows = (d.sources || []).map(s => {
      const okCls = /ok/i.test(s.status) ? 'text-success' : 'text-danger';
      return `<tr style="color:#e6edf3">
        <td class="small" style="color:#e6edf3">${escapeHtml(s.name)}</td>
        <td class="small" style="color:#e6edf3">${escapeHtml(s.type)}</td>
        <td class="small font-monospace text-end" style="color:#e6edf3">${(s.count||0).toLocaleString()}</td>
        <td class="small ${okCls}">${escapeHtml(s.status||'-')}</td>
      </tr>`;
    }).join('');
    srcTbody.innerHTML = rows || '<tr><td colspan="4" class="text-center" style="color:#e6edf3">피드 로딩 중...</td></tr>';
  }

  const ipBox = document.getElementById('ti-sample-ips');
  if (ipBox) {
    const ips = d.sample_bad_ips || [];
    ipBox.innerHTML = ips.length
      ? ips.map(ip => `<div class="p-1 border-bottom border-secondary">${escapeHtml(ip)}</div>`).join('')
      : '<div class="text-muted p-2">샘플 없음</div>';
  }
  const urlBox = document.getElementById('ti-sample-urls');
  if (urlBox) {
    const urls = d.sample_bad_urls || [];
    urlBox.innerHTML = urls.length
      ? urls.map(u => `<div class="p-1 border-bottom border-secondary">${escapeHtml(u)}</div>`).join('')
      : '<div class="text-muted p-2">샘플 없음</div>';
  }

  // 매칭 리스트
  renderTiMatches(d.matches || []);

  svgDonut('ti-donut', [
    { label: '악성 IP', value: stats.bad_ip_count || 0, color: '#f85149' },
    { label: '악성 URL', value: stats.bad_url_count || 0, color: '#f0a500' },
  ], ((stats.bad_ip_count || 0) + (stats.bad_url_count || 0)).toLocaleString(), '총 IoC');
  svgHBars('ti-bars', (d.sources || []).slice(0, 6).map(s => ({
    label: s.name, value: s.count || 0, color: /ok/i.test(s.status || '') ? '#39d0d8' : '#8b949e',
  })), '개');
}

function renderTiMatches(matches) {
  const list = document.getElementById('ti-match-list');
  const ovList = document.getElementById('ov-ti-recent');
  const html = matches.length
    ? matches.map(tiMatchHtml).join('')
    : '<div class="text-muted text-center p-3">매칭 대기 중...</div>';
  if (list) list.innerHTML = html;
  if (ovList) ovList.innerHTML = matches.length
    ? matches.slice(0, 6).map(tiMatchHtml).join('')
    : '<div class="text-muted p-2">매칭 대기 중...</div>';
}

function tiMatchHtml(m) {
  const kindCls = m.kind === 'ip' ? 'bg-danger' : 'bg-orange';
  const dirIcon = m.direction === 'inbound' ? 'fa-arrow-down' : 'fa-arrow-up';
  const time = (m.timestamp || '').split(' ')[1] || m.timestamp || '';
  return `<div class="ti-match-item p-2 border-bottom border-secondary" style="color:#e6edf3">
    <div class="d-flex align-items-center gap-2 mb-1">
      <span class="badge ${kindCls}" style="font-size:9px">${(m.kind||'').toUpperCase()}</span>
      <span class="badge bg-danger" style="font-size:9px">CRITICAL</span>
      <i class="fa ${dirIcon} text-muted small"></i>
      <span class="text-muted small">${time}</span>
    </div>
    <div class="small font-monospace">${escapeHtml(m.indicator || '')}</div>
    <div class="small text-muted">
      ${m.local_ip ? `내부: ${escapeHtml(m.local_ip)}` : ''} ${m.port ? `· 포트 ${m.port}` : ''}
    </div>
    <div class="small">${escapeHtml(m.description || '')}</div>
  </div>`;
}

function refreshThreatIntel() {
  fetch('/api/threat-intel/refresh', { method: 'POST' })
    .then(r => r.json())
    .then(() => {
      setTimeout(loadThreatIntel, 1500);
    });
}

function checkThreatIntel() {
  const ip  = document.getElementById('ti-check-ip').value.trim();
  const url = document.getElementById('ti-check-url').value.trim();
  if (!ip && !url) return;
  fetch('/api/threat-intel/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, url }),
  })
    .then(r => r.json())
    .then(d => {
      const box = document.getElementById('ti-check-result');
      if (!box) return;
      const ipMsg = d.ip ? (d.ip_malicious
          ? `<span class="badge bg-danger">악성</span> ${escapeHtml(d.ip)}`
          : `<span class="badge bg-success">정상</span> ${escapeHtml(d.ip)}`)
        : '';
      const urlMsg = d.url ? (d.url_malicious
          ? `<span class="badge bg-danger">악성</span> ${escapeHtml(d.url)}`
          : `<span class="badge bg-success">정상</span> ${escapeHtml(d.url)}`)
        : '';
      box.innerHTML = [ipMsg, urlMsg].filter(Boolean).join('<br/>');
    });
}

const tiMatchCache = [];
function bumpTiSidebar(n) {
  const badge = document.getElementById('sidebar-ti-count');
  if (!badge) return;
  const cur = parseInt(badge.textContent || '0', 10) || 0;
  badge.textContent = (cur + n).toLocaleString();
}

socket.on('ti_match', m => {
  tiMatchCache.unshift(m);
  while (tiMatchCache.length > 60) tiMatchCache.pop();
  renderTiMatches(tiMatchCache);
  const totalEl = document.getElementById('ti-total-match');
  if (totalEl) totalEl.textContent = (parseInt(totalEl.textContent.replace(/,/g, '')) + 1).toLocaleString();
  const ovTotal = document.getElementById('ov-ti-match');
  if (ovTotal) ovTotal.textContent = (parseInt(ovTotal.textContent.replace(/,/g, '')) + 1).toLocaleString();
  bumpTiSidebar(1);
  pushLive('ti', 'high',
    `<b>IoC 매칭</b> <span class="lv-ip">${escapeHtml(m.indicator || '')}</span> ` +
    `<span class="text-muted">${escapeHtml(m.description || '')}</span>`);
});

socket.on('ti_feed_update', d => {
  renderThreatIntel(d);
});

