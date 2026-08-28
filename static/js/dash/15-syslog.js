/* dashboard/15-syslog.js — Syslog 수신(원격 침해시도 수집) 패널 */
(function () {
  let syslogEventsBuffer = [];

  function loadSyslog() {
    fetch('/api/integrations/syslog')
      .then(r => r.json())
      .then(renderSyslogStatus)
      .catch(() => {});
  }

  function renderSyslogStatus(d) {
    const stats = d.stats || {};
    const set = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = (v ?? 0).toLocaleString();
    };
    set('syslog-total', stats.total);
    set('syslog-suspicious', stats.suspicious);
    set('syslog-unique-ips', stats.unique_ips);
    set('syslog-hosts', stats.unique_hosts);
    const badge = document.getElementById('sidebar-syslog-count');
    if (badge) badge.textContent = (stats.suspicious || 0).toLocaleString();

    const cfg = d.config || {};
    const hint = document.getElementById('syslog-bind-hint');
    if (hint) {
      const mode = stats.mode === 'real' ? '<span class="badge bg-success">수신 대기중</span>'
                : stats.mode === 'demo' ? '<span class="badge bg-info text-dark">데모</span>'
                : '<span class="badge bg-secondary">비활성</span>';
      hint.innerHTML = `수신 주소 <code>${escapeHtml(stats.bind || (cfg.bind + ':' + cfg.port))}</code> (UDP+TCP) ${mode}` +
        (stats.received ? ` · 실수신 ${(stats.received).toLocaleString()}건` : '');
    }

    const hostsBox = document.getElementById('syslog-top-hosts');
    if (hostsBox) {
      const top = stats.top_hosts || [];
      hostsBox.innerHTML = top.length
        ? top.map(([h, cnt], i) => `
            <div class="d-flex justify-content-between p-1 border-bottom border-secondary small">
              <span style="color:#e6edf3">${i + 1}. ${escapeHtml(h)}</span>
              <span class="text-info">${cnt.toLocaleString()}건</span>
            </div>`).join('')
        : '<div class="text-muted p-2">데이터 없음</div>';
    }

    const topBox = document.getElementById('syslog-top-ips');
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

    syslogEventsBuffer = d.events || [];
    renderSyslogEvents();
  }

  function syslogEventRow(e) {
    const sevCls = e.severity === 'CRITICAL' ? 'bg-danger'
                : e.severity === 'HIGH'     ? 'bg-orange'
                : e.severity === 'MEDIUM'   ? 'bg-warning text-dark'
                : 'bg-secondary';
    const demoTag = e.demo ? ' <span class="badge bg-info text-dark" style="font-size:8px">데모</span>' : '';
    return `
      <tr ${e.suspicious ? 'style="background:rgba(248,81,73,.08)"' : ''}>
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(e.timestamp)}</td>
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(e.host)}${demoTag}</td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(e.ip || '-')}</td>
        <td class="small font-monospace text-truncate" style="max-width:320px;color:#e6edf3"
            title="${escapeHtml(e.message)}">${escapeHtml(e.message)}</td>
        <td class="small"><span class="badge ${sevCls}" style="font-size:9px">${escapeHtml(e.category)}</span></td>
      </tr>`;
  }

  function renderSyslogEvents() {
    const tbody = document.getElementById('syslog-events-tbody');
    if (!tbody) return;
    const suspiciousOnly = document.getElementById('syslog-suspicious-only')?.checked;
    const rows = syslogEventsBuffer
      .filter(e => !suspiciousOnly || e.suspicious)
      .slice(0, 200);
    tbody.innerHTML = rows.length
      ? rows.map(syslogEventRow).join('')
      : '<tr><td colspan="5" class="text-muted text-center p-3">이벤트 없음</td></tr>';
  }

  socket.on('syslog_event', e => {
    syslogEventsBuffer.unshift(e);
    while (syslogEventsBuffer.length > 500) syslogEventsBuffer.pop();
    const bump = (id, n) => {
      const el = document.getElementById(id);
      if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g, '')) || 0) + n).toLocaleString();
    };
    bump('syslog-total', 1);
    if (e.suspicious) {
      bump('syslog-suspicious', 1);
      bump('sidebar-syslog-count', 1);
      // 의심 이벤트만 통합 라이브 스트림에 노출
      pushLive('siem', e.severity,
        `<b>${escapeHtml(e.category)}</b> <span class="lv-ip">${escapeHtml(e.ip || '-')}</span> ` +
        `<span class="text-muted">(syslog/${escapeHtml(e.host)})</span>`);
    }
    const panel = document.getElementById('panel-syslog');
    if (panel && !panel.classList.contains('d-none')) {
      renderSyslogEvents();
    }
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadSyslog, renderSyslogEvents,
  });
})();
