/* Snort IDS · UFW 상태 — 보이는 패널만 주기 갱신 */
(function () {
  let _snortStatus = null;

  function serviceBadge(state) {
    const active = state?.active === 'active';
    return `<span class="badge ${active ? 'bg-success' : 'bg-danger'}">${active ? 'ACTIVE' : escapeHtml(state?.active || 'UNKNOWN')}</span>`;
  }

  function renderSnortStatus(d) {
    _snortStatus = d;
    const sys = d.system || {};
    const snortUp = sys.snort_service?.active === 'active';
    const ufwUp = sys.ufw_service?.active === 'active';
    const both = snortUp && ufwUp;
    const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };

    setText('snort-alert-count', Number(d.alerts || 0).toLocaleString());
    setText('snort-invalid-count', Number(d.invalid || 0).toLocaleString());
    setText('sidebar-snort-count', Number(d.alerts || 0).toLocaleString());
    const snortEl = document.getElementById('snort-service');
    const ufwEl = document.getElementById('ufw-service');
    if (snortEl) snortEl.innerHTML = serviceBadge(sys.snort_service);
    if (ufwEl) ufwEl.innerHTML = serviceBadge(sys.ufw_service);

    const live = document.getElementById('snort-live-badge');
    if (live) { live.textContent = both ? '보호 활성' : '점검 필요'; live.className = `badge ms-3 ${both ? 'bg-success' : 'bg-danger'}`; }
    const cfg = document.getElementById('snort-config');
    if (cfg) cfg.innerHTML = `인터페이스 <b class="text-cyan">${escapeHtml(sys.interface || '—')}</b><br>` +
      `HOME_NET <code>${escapeHtml(sys.home_net || '—')}</code><br>` +
      `Fast log <code>${escapeHtml(d.alert_path || '—')}</code><br>` +
      `수집기 <b class="${d.status === 'active' ? 'text-success' : 'text-warning'}">${escapeHtml(d.status || '—')}</b>`;
    const policy = document.getElementById('ufw-policy');
    if (policy) policy.innerHTML = `기본 정책 <b>${escapeHtml(sys.firewall_policy || '—')}</b><br>` +
      `보호 경로 ${(sys.protected_paths || []).map(x => `<span class="badge bg-secondary me-1">${escapeHtml(x)}</span>`).join('')}<br>` +
      `<span class="text-warning">실제 차단은 SOAR 승인 게이트 통과 후 수행</span>`;

    setText('overview-snort-state', snortUp ? 'ACTIVE' : 'DOWN');
    setText('overview-ufw-state', ufwUp ? 'ACTIVE' : 'DOWN');
    setText('overview-snort-interface', sys.interface || '—');
    ['overview-snort-state', 'overview-ufw-state'].forEach(id => {
      const el = document.getElementById(id); if (el) el.className = (el.textContent === 'ACTIVE' ? 'text-success' : 'text-danger');
    });
    const ov = document.getElementById('overview-security-badge');
    if (ov) { ov.textContent = both ? '보호 활성' : '점검 필요'; ov.className = `badge ms-auto ${both ? 'bg-success' : 'bg-danger'}`; }

    const tbody = document.getElementById('snort-events');
    if (tbody && (d.recent || []).length) tbody.innerHTML = d.recent.map(e => `<tr>
      <td>${escapeHtml(e.timestamp || '—')}</td><td>${Number(e.priority) === 1 ? '<span class="badge bg-danger">P1</span>' : `<span class="badge bg-warning text-dark">P${Number(e.priority)||'—'}</span>`}</td>
      <td><code>${Number(e.sid)||'—'}</code></td><td>${escapeHtml(e.message || '')}</td>
      <td class="font-monospace">${escapeHtml(e.src_ip || '')}${e.src_port ? ':'+Number(e.src_port) : ''}</td>
      <td class="font-monospace">${escapeHtml(e.dst_ip || '')}${e.dst_port ? ':'+Number(e.dst_port) : ''}</td><td>${escapeHtml(e.protocol || '')}</td></tr>`).join('');
    const quality = document.getElementById('snort-sid-quality');
    const excluded = new Set((d.excluded_sids || []).map(Number));
    if (quality && (d.sid_quality || []).length) quality.innerHTML = d.sid_quality.map(s => `<tr>
      <td><code>${Number(s.sid)}</code></td><td>${Number(s.total)}</td><td class="text-danger">${Number(s.tp)}</td>
      <td class="text-success">${Number(s.fp)}</td><td>${Number(s.unreviewed)}</td>
      <td>${s.accuracy == null ? '—' : Number(s.accuracy).toFixed(1)+'%'}</td>
      <td>${excluded.has(Number(s.sid)) ? '<span class="badge bg-secondary">자동 차단 제외</span>' : '<span class="badge bg-warning text-dark">교차검증 대상</span>'}</td></tr>`).join('');
  }

  function loadSnort(force = false) {
    if (!force && document.hidden) return;
    return fetch('/api/integrations/snort').then(r => r.json()).then(renderSnortStatus).catch(() => {});
  }

  socket.on('snort_alert', event => {
    if (_snortStatus) {
      _snortStatus.alerts = Number(_snortStatus.alerts || 0) + 1;
      _snortStatus.recent = [event, ...(_snortStatus.recent || [])].slice(0, 20);
      if (isPanelVisible('snort') || isPanelVisible('overview')) renderSnortStatus(_snortStatus);
    }
  });

  setInterval(() => {
    if (!document.hidden && (isPanelVisible('snort') || isPanelVisible('overview'))) loadSnort();
  }, 10000);
  loadSnort();

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadSnort,
  });
})();
