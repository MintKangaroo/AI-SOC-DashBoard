/* dashboard/16-honeypot.js — 허니팟(유인 서비스 침해 포착) 패널 */
(function () {
  let honeypotEventsBuffer = [];

  function loadHoneypot() {
    fetch('/api/integrations/honeypot')
      .then(r => r.json())
      .then(renderHoneypotStatus)
      .catch(() => {});
  }

  function renderHoneypotStatus(d) {
    const stats = d.stats || {};
    const set = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = (v ?? 0).toLocaleString();
    };
    set('honeypot-hits', stats.total_hits);
    set('honeypot-interactions', stats.interactions);
    set('honeypot-ips', stats.unique_ips);
    set('honeypot-ports', stats.ports_open);
    const badge = document.getElementById('sidebar-honeypot-count');
    if (badge) badge.textContent = (stats.total_hits || 0).toLocaleString();

    const hint = document.getElementById('honeypot-bind-hint');
    if (hint) {
      const mode = stats.mode === 'real' ? '<span class="badge bg-success">가동중</span>'
                : stats.mode === 'demo' ? '<span class="badge bg-info text-dark">데모</span>'
                : '<span class="badge bg-secondary">비활성</span>';
      const ports = (stats.ports || []).join(', ');
      hint.innerHTML = `바인드 <code>${escapeHtml(stats.bind || '-')}</code> · 포트 <code>${escapeHtml(ports)}</code> ${mode}` +
        (stats.mode === 'real'
          ? ' <span class="text-muted">— 실포착은 0.0.0.0 바인드+외부 노출 필요</span>' : '');
    }

    // 서비스별 막대
    const bs = (stats.by_service || []).slice(0, 7).map(([svc, cnt]) => ({
      label: svc, value: cnt, color: '#f0a500',
    }));
    if (typeof svgHBars === 'function') svgHBars('honeypot-bars', bs, '건');

    const topBox = document.getElementById('honeypot-top-ips');
    if (topBox) {
      const top = stats.top_ips || [];
      topBox.innerHTML = top.length
        ? top.map(([ip, cnt], i) => `
            <div class="d-flex justify-content-between p-1 border-bottom border-secondary small">
              <span class="font-monospace" style="color:#e6edf3">${i + 1}. ${escapeHtml(ip)}</span>
              <span class="text-warning">${cnt.toLocaleString()}건</span>
            </div>`).join('')
        : '<div class="text-muted p-2">데이터 없음</div>';
    }

    honeypotEventsBuffer = d.events || [];
    renderHoneypotEvents();
  }

  function honeypotEventRow(e) {
    const sevCls = e.severity === 'CRITICAL' ? 'bg-danger' : 'bg-orange';
    const demoTag = e.demo ? ' <span class="badge bg-info text-dark" style="font-size:8px">데모</span>' : '';
    const payload = e.interacted
      ? `<span class="text-danger font-monospace">${escapeHtml(e.payload)}</span>`
      : '<span class="text-muted">연결만</span>';
    return `
      <tr style="background:rgba(240,165,0,.06)">
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(e.timestamp)}</td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(e.ip)}${demoTag}</td>
        <td class="small"><span class="badge bg-secondary">${escapeHtml(e.service)}:${e.port}</span></td>
        <td class="small text-truncate" style="max-width:300px">${payload}</td>
        <td class="small"><span class="badge ${sevCls}" style="font-size:9px">${escapeHtml(e.severity)}</span></td>
      </tr>`;
  }

  function renderHoneypotEvents() {
    const tbody = document.getElementById('honeypot-events-tbody');
    if (!tbody) return;
    const rows = honeypotEventsBuffer.slice(0, 200);
    tbody.innerHTML = rows.length
      ? rows.map(honeypotEventRow).join('')
      : '<tr><td colspan="5" class="text-muted text-center p-3">접촉 없음</td></tr>';
  }

  socket.on('honeypot_hit', e => {
    honeypotEventsBuffer.unshift(e);
    while (honeypotEventsBuffer.length > 500) honeypotEventsBuffer.pop();
    const bump = (id, n) => {
      const el = document.getElementById(id);
      if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g, '')) || 0) + n).toLocaleString();
    };
    bump('honeypot-hits', 1);
    bump('sidebar-honeypot-count', 1);
    if (e.interacted) bump('honeypot-interactions', 1);
    pushLive('siem', e.severity,
      `<b>허니팟 ${escapeHtml(e.service)}</b> 접촉 <span class="lv-ip">${escapeHtml(e.ip)}</span>` +
      (e.interacted ? ` <span class="text-danger">입력감지</span>` : ''));
    const panel = document.getElementById('panel-honeypot');
    if (panel && !panel.classList.contains('d-none')) {
      renderHoneypotEvents();
    }
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadHoneypot,
  });
})();
