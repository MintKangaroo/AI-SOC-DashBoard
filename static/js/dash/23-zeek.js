/* Zeek notice.log — 보이는 패널만 주기 갱신. 22-suricata.js 와 같은 구조 */
(function () {
  let _zeekStatus = null;

  function renderZeek(d) {
    _zeekStatus = d;
    const sys = d.system || {};
    const up = sys.zeek_service?.active === 'active';
    const feeding = d.status === 'active';
    const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    const byNote = d.by_note || {};

    setText('zeek-alert-count', Number(d.alerts || 0).toLocaleString());
    setText('zeek-note-kinds', Object.keys(byNote).length.toLocaleString());
    setText('zeek-invalid-count', Number(d.invalid || 0).toLocaleString());
    setText('sidebar-zeek-count', Number(d.alerts || 0).toLocaleString());

    const svc = document.getElementById('zeek-service');
    if (svc) svc.innerHTML = `<span class="badge ${up ? 'bg-success' : 'bg-secondary'}">${up ? 'ACTIVE' : escapeHtml(sys.zeek_service?.active || 'UNKNOWN')}</span>`;
    const live = document.getElementById('zeek-live-badge');
    if (live) {
      live.textContent = !d.enabled ? '비활성' : feeding ? '수집 중' : d.status === 'waiting' ? 'notice.log 대기' : escapeHtml(d.status || '—');
      live.className = `badge ms-3 ${feeding ? 'bg-success' : 'bg-secondary'}`;
    }
    const cfg = document.getElementById('zeek-config');
    if (cfg) cfg.innerHTML = `notice.log <code>${escapeHtml(d.notice_path || '—')}</code><br>` +
      `수집기 <b class="${feeding ? 'text-success' : 'text-warning'}">${escapeHtml(d.status || '—')}</b>` +
      (d.status === 'waiting' ? ' <span class="text-muted">— 파일이 생기면 자동으로 붙습니다</span>' : '') + '<br>' +
      `<span class="text-muted">심각도 규칙 ${Object.keys(d.note_rules || {}).length}종 · 그 외 note 는 MEDIUM</span>`;
    const bn = document.getElementById('zeek-by-note');
    if (bn) {
      const entries = Object.entries(byNote);
      bn.innerHTML = entries.length
        ? entries.map(([k, v]) => `<span class="badge badge-neutral me-1 mb-1">${escapeHtml(k)} <b>${Number(v).toLocaleString()}</b></span>`).join('')
        : '아직 수신 없음';
    }
    const tbody = document.getElementById('zeek-events');
    if (tbody && (d.recent || []).length) tbody.innerHTML = d.recent.map(e => `<tr>
      <td class="text-nowrap">${escapeHtml(e.timestamp || '—')}</td><td>${sevBadge(e.severity)}</td>
      <td><code>${escapeHtml(e.note || '')}</code></td><td>${escapeHtml(e.msg || e.sub || '')}</td>
      <td class="font-monospace">${escapeHtml(e.src_ip || '')}${e.src_port ? ':' + escapeHtml(String(e.src_port)) : ''}</td>
      <td class="font-monospace">${escapeHtml(e.dst_ip || '')}${e.dst_port ? ':' + escapeHtml(String(e.dst_port)) : ''}</td>
      <td>${escapeHtml(e.proto || '')}</td></tr>`).join('');
  }

  function loadZeek(force = false) {
    if (!force && document.hidden) return;
    return fetch('/api/integrations/zeek').then(r => r.json()).then(renderZeek).catch(() => {});
  }

  socket.on('zeek_notice', ev => {
    if (_zeekStatus) {
      _zeekStatus.alerts = Number(_zeekStatus.alerts || 0) + 1;
      _zeekStatus.recent = [ev, ...(_zeekStatus.recent || [])].slice(0, 20);
      _zeekStatus.by_note = _zeekStatus.by_note || {};
      _zeekStatus.by_note[ev.note] = (_zeekStatus.by_note[ev.note] || 0) + 1;
      _zeekStatus.status = 'active';
    }
    const badge = document.getElementById('sidebar-zeek-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g, '')) || 0) + 1).toLocaleString();
    if (_zeekStatus && isPanelVisible('zeek')) renderZeek(_zeekStatus);
  });

  setInterval(() => {
    if (!document.hidden && isPanelVisible('zeek')) loadZeek();
  }, 10000);

  /* 이 파일이 다른 파일·data-action 에 공개하는 이름. 여기 없는 것은 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadZeek,
  });
})();
