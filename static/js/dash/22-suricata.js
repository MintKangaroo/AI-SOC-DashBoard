/* Suricata IDS (EVE JSON) — 보이는 패널만 주기 갱신. 18-snort.js 와 같은 구조 */
(function () {
  let _status = null;

  function sevBadgeRaw(s) {
    const n = Number(s);
    if (n === 1) return '<span class="badge bg-danger">S1</span>';
    if (n === 2) return '<span class="badge bg-warning text-dark">S2</span>';
    return `<span class="badge bg-secondary">S${n || '—'}</span>`;
  }

  function renderSuricata(d) {
    _status = d;
    const sys = d.system || {};
    const up = sys.suricata_service?.active === 'active';
    const feeding = d.status === 'active';
    const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    const skippedTotal = Object.values(d.skipped_by_type || {}).reduce((a, b) => a + Number(b), 0);

    setText('suricata-alert-count', Number(d.alerts || 0).toLocaleString());
    setText('suricata-skipped-count', skippedTotal.toLocaleString());
    setText('suricata-invalid-count', Number(d.invalid || 0).toLocaleString());
    setText('sidebar-suricata-count', Number(d.alerts || 0).toLocaleString());

    const svc = document.getElementById('suricata-service');
    if (svc) svc.innerHTML = `<span class="badge ${up ? 'bg-success' : 'bg-secondary'}">${up ? 'ACTIVE' : escapeHtml(sys.suricata_service?.active || 'UNKNOWN')}</span>`;
    const live = document.getElementById('suricata-live-badge');
    if (live) {
      live.textContent = !d.enabled ? '비활성' : feeding ? '수집 중' : d.status === 'waiting' ? 'eve.json 대기' : escapeHtml(d.status || '—');
      live.className = `badge ms-3 ${feeding ? 'bg-success' : 'bg-secondary'}`;
    }
    const cfg = document.getElementById('suricata-config');
    if (cfg) cfg.innerHTML = `인터페이스 <b class="text-cyan">${escapeHtml(sys.interface || '—')}</b><br>` +
      `EVE 경로 <code>${escapeHtml(d.eve_path || '—')}</code><br>` +
      `수집기 <b class="${feeding ? 'text-success' : 'text-warning'}">${escapeHtml(d.status || '—')}</b>` +
      (d.status === 'waiting' ? ' <span class="text-muted">— 파일이 생기면 자동으로 붙습니다</span>' : '') + '<br>' +
      `자동 차단 근거 제외 SID ${(d.excluded_sids || []).length ? d.excluded_sids.map(s => `<code>${Number(s)}</code>`).join(' ') : '<span class="text-muted">없음</span>'}`;
    const sk = document.getElementById('suricata-skipped');
    if (sk) {
      const entries = Object.entries(d.skipped_by_type || {});
      sk.innerHTML = entries.length
        ? entries.map(([k, v]) => `<span class="badge badge-neutral me-1 mb-1">${escapeHtml(k)} <b>${Number(v).toLocaleString()}</b></span>`).join('') +
          '<div class="text-muted mt-2">alert 만 알림이 됩니다. 나머지는 여기서 비율만 봅니다.</div>'
        : '아직 수신 없음';
    }

    const tbody = document.getElementById('suricata-events');
    if (tbody && (d.recent || []).length) tbody.innerHTML = d.recent.map(e => {
      const ctx = e.http_host || e.http_url ? `${escapeHtml(e.http_host || '')}${escapeHtml(e.http_url || '')}`
                : e.dns_query ? `DNS ${escapeHtml(e.dns_query)}` : (e.app_proto ? escapeHtml(e.app_proto) : '—');
      return `<tr>
      <td class="text-nowrap">${escapeHtml((e.timestamp || '—').replace('T', ' ').slice(0, 19))}</td><td>${sevBadgeRaw(e.severity)}</td>
      <td><code>${Number(e.sid) || '—'}</code></td><td>${escapeHtml(e.signature || '')}</td><td class="text-muted">${escapeHtml(e.category || '')}</td>
      <td class="font-monospace">${escapeHtml(e.src_ip || '')}${e.src_port ? ':' + Number(e.src_port) : ''}</td>
      <td class="font-monospace">${escapeHtml(e.dst_ip || '')}${e.dst_port ? ':' + Number(e.dst_port) : ''}</td>
      <td>${escapeHtml(e.protocol || '')}</td><td class="text-muted">${ctx}</td></tr>`;
    }).join('');

    const quality = document.getElementById('suricata-sid-quality');
    const excluded = new Set((d.excluded_sids || []).map(Number));
    if (quality && (d.sid_quality || []).length) quality.innerHTML = d.sid_quality.map(s => `<tr>
      <td><code>${Number(s.sid)}</code></td><td>${Number(s.total)}</td><td class="text-danger">${Number(s.tp)}</td>
      <td class="text-success">${Number(s.fp)}</td><td>${Number(s.unreviewed)}</td>
      <td>${s.accuracy == null ? '—' : Number(s.accuracy).toFixed(1) + '%'}</td>
      <td>${excluded.has(Number(s.sid)) ? '<span class="badge bg-secondary">자동 차단 제외</span>' : '<span class="badge bg-warning text-dark">교차검증 대상</span>'}</td></tr>`).join('');
  }

  function loadSuricata(force = false) {
    if (!force && document.hidden) return;
    return fetch('/api/integrations/suricata').then(r => r.json()).then(renderSuricata).catch(() => {});
  }

  socket.on('suricata_alert', event => {
    if (_status) {
      _status.alerts = Number(_status.alerts || 0) + 1;
      _status.recent = [event, ...(_status.recent || [])].slice(0, 20);
      _status.status = 'active';
    }
    const badge = document.getElementById('sidebar-suricata-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g, '')) || 0) + 1).toLocaleString();
    if (_status && isPanelVisible('suricata')) renderSuricata(_status);
  });

  setInterval(() => {
    if (!document.hidden && isPanelVisible('suricata')) loadSuricata();
  }, 10000);
  // 첫 로드는 showPanel('suricata') 훅(01-core)이 맡는다 — 패널이 실체화되기 전엔 요소가 없다.

  /* 이 파일이 다른 파일·data-action 에 공개하는 이름. 여기 없는 것은 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadSuricata,
  });
})();
