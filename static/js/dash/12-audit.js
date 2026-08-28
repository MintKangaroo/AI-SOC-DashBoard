/* dashboard/12-audit.js — 전역 감사 로그(분석가 조치 이력) 패널 */
(function () {

  let _auditPage = 1, _auditPages = 1, _auditActionsLoaded = false;

  const AUDIT_ACTION_CLS = {
    ALERT_ACK: 'bg-warning text-dark', ALERT_CLOSE: 'bg-secondary', ALERT_REOPEN: 'bg-danger',
    SOAR_BLOCK: 'bg-danger', SOAR_UNBLOCK: 'bg-info text-dark',
    INCIDENT_STATUS: 'bg-info text-dark', INCIDENT_ASSIGN: 'bg-secondary', INCIDENT_NOTE: 'bg-secondary',
    WATCHLIST_ADD: 'bg-success', WATCHLIST_REMOVE: 'bg-secondary', ALERT_ARCHIVE: 'bg-secondary',
  };

  function loadAudit() {
    if (!_auditActionsLoaded) {
      fetch('/api/audit?limit=1').then(r => r.json()).then(d => {
        const sel = document.getElementById('audit-action');
        if (sel && d.labels) {
          Object.entries(d.labels).forEach(([k, v]) => {
            const o = document.createElement('option'); o.value = k; o.textContent = v; sel.appendChild(o);
          });
        }
        _auditActionsLoaded = true;
      }).catch(() => {});
    }
    searchAudit(1);
  }

  function _auditParams() {
    const p = new URLSearchParams();
    const g = id => (document.getElementById(id)?.value || '').trim();
    if (g('audit-from'))   p.set('from', g('audit-from'));
    if (g('audit-to'))     p.set('to', g('audit-to'));
    if (g('audit-action')) p.set('action', g('audit-action'));
    if (g('audit-actor'))  p.set('actor', g('audit-actor'));
    return p;
  }

  function searchAudit(page) {
    _auditPage = page || 1;
    const p = _auditParams();
    p.set('page', _auditPage); p.set('limit', 50);
    const tbody = document.getElementById('audit-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">검색 중…</td></tr>';
    fetch('/api/audit?' + p.toString()).then(r => r.json()).then(renderAudit)
      .catch(() => { if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger py-4">검색 실패</td></tr>'; });
  }

  function renderAudit(d) {
    const rows = d.events || [];
    _auditPage = d.page || 1; _auditPages = d.pages || 1;
    const tb = document.getElementById('audit-total-badge');
    if (tb) tb.textContent = (d.total || 0).toLocaleString() + '건';

    const tbody = document.getElementById('audit-tbody');
    if (tbody) {
      tbody.innerHTML = rows.length ? rows.map(e => `
        <tr>
          <td class="font-monospace small text-nowrap">${escapeHtml(e.ts || '')}</td>
          <td class="small"><i class="fa fa-user-shield me-1 text-muted"></i>${escapeHtml(e.actor || '')}</td>
          <td><span class="badge ${AUDIT_ACTION_CLS[e.action] || 'bg-dark'}">${escapeHtml(e.action_label || e.action)}</span></td>
          <td class="font-monospace small">${escapeHtml(e.target || '')}</td>
          <td class="small text-muted">${escapeHtml(e.detail || '')}</td>
        </tr>`).join('')
        : '<tr><td colspan="5" class="text-center text-muted py-4">조건에 맞는 기록이 없습니다.</td></tr>';
    }
    const summary = document.getElementById('audit-summary');
    if (summary) {
      const start = rows.length ? (_auditPage - 1) * (d.limit || 50) + 1 : 0;
      summary.textContent = `${(d.total || 0).toLocaleString()}건 중 ${start.toLocaleString()}~${(start + rows.length - 1).toLocaleString()} 표시`;
    }
    const pl = document.getElementById('audit-page-label');
    if (pl) pl.textContent = `${_auditPage} / ${_auditPages}`;
    const prev = document.getElementById('audit-prev'), next = document.getElementById('audit-next');
    if (prev) prev.disabled = _auditPage <= 1;
    if (next) next.disabled = _auditPage >= _auditPages;
  }

  function pageAudit(delta) {
    const n = _auditPage + delta;
    if (n < 1 || n > _auditPages) return;
    searchAudit(n);
  }

  function resetAudit() {
    ['audit-from', 'audit-to', 'audit-actor'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    const sel = document.getElementById('audit-action'); if (sel) sel.value = '';
    searchAudit(1);
  }

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadAudit, pageAudit, resetAudit, searchAudit,
  });
})();
