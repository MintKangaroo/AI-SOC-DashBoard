/* dashboard/09-alert-history.js — 알림 이력 검색(전체 DB) + CSV 내보내기 */

let _ahPage = 1;
let _ahPages = 1;
let _ahTypesLoaded = false;

function _ensureAlertHistoryTypes() {
  if (_ahTypesLoaded) return Promise.resolve();
  return fetch('/api/alerts/history?limit=1').then(r => r.json()).then(d => {
    const sel = document.getElementById('ah-type');
    if (sel && d.labels) {
      Object.entries(d.labels).forEach(([k, v]) => {
        if (sel.querySelector(`option[value="${CSS.escape(k)}"]`)) return;
        const o = document.createElement('option');
        o.value = k; o.textContent = v; sel.appendChild(o);
      });
    }
    _ahTypesLoaded = true;
  });
}

/* 현재 필터 → 쿼리스트링 */
function _ahParams() {
  const p = new URLSearchParams();
  const g = id => (document.getElementById(id)?.value || '').trim();
  if (g('ah-from'))     p.set('from', g('ah-from'));
  if (g('ah-to'))       p.set('to', g('ah-to'));
  if (g('ah-severity')) p.set('severity', g('ah-severity'));
  if (g('ah-status'))   p.set('status', g('ah-status'));
  if (g('ah-type'))     p.set('threat_type', g('ah-type'));
  if (g('ah-ip'))       p.set('ip', g('ah-ip'));
  if (g('ah-text'))     p.set('text', g('ah-text'));
  if (g('ah-scope'))    p.set('scope', g('ah-scope'));
  return p;
}

/* 패널 최초 진입: 위협 유형 옵션 채우고 1페이지 검색 */
function loadAlertHistory() {
  _ensureAlertHistoryTypes().then(() => searchAlertHistory(1)).catch(() => searchAlertHistory(1));
}

function openAlertGroup(srcIp, threatType) {
  showPanel('alert-history');
  _ensureAlertHistoryTypes().then(() => {
    const ip = document.getElementById('ah-ip');
    const type = document.getElementById('ah-type');
    if (ip) ip.value = srcIp || '';
    if (type) type.value = threatType || '';
    searchAlertHistory(1);
  }).catch(() => {});
}

function searchAlertHistory(page) {
  _ahPage = page || 1;
  const p = _ahParams();
  p.set('page', _ahPage);
  p.set('limit', 50);
  const tbody = document.getElementById('ah-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">검색 중…</td></tr>';

  fetch('/api/alerts/history?' + p.toString())
    .then(r => r.json())
    .then(d => renderAlertHistory(d))
    .catch(() => {
      if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-4">검색 실패</td></tr>';
    });
}

function renderAlertHistory(d) {
  const rows = d.alerts || [];
  _ahPage = d.page || 1;
  _ahPages = d.pages || 1;

  const totalBadge = document.getElementById('ah-total-badge');
  if (totalBadge) totalBadge.textContent = (d.total || 0).toLocaleString() + '건';

  const tbody = document.getElementById('ah-tbody');
  if (tbody) {
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">조건에 맞는 알림이 없습니다.</td></tr>';
    } else {
      tbody.innerHTML = rows.map(a => `
        <tr>
          <td class="font-monospace small text-nowrap">${escapeHtml(a.timestamp || '')}</td>
          <td>${sevBadge(a.severity)}</td>
          <td class="small">${escapeHtml(a.threat_label || a.threat_type || '')}</td>
          <td class="font-monospace small">${escapeHtml(a.src_ip || '')}</td>
          <td class="font-monospace small">${escapeHtml(a.dst_ip || '')}</td>
          <td class="small">${escapeHtml(a.description || '')}</td>
          <td>${_ahStatusBadge(a.status)}${a.archived ? ' <span class="badge bg-secondary" title="아카이브 보관 — 조회 전용">보관</span>' : ''}</td>
        </tr>`).join('');
    }
  }

  const summary = document.getElementById('ah-summary');
  if (summary) {
    const shown = rows.length;
    const start = shown ? (_ahPage - 1) * (d.limit || 50) + 1 : 0;
    summary.textContent = `${(d.total || 0).toLocaleString()}건 중 ${start.toLocaleString()}~${(start + shown - 1).toLocaleString()} 표시`;
  }
  const pageLabel = document.getElementById('ah-page-label');
  if (pageLabel) pageLabel.textContent = `${_ahPage} / ${_ahPages}`;
  const prev = document.getElementById('ah-prev');
  const next = document.getElementById('ah-next');
  if (prev) prev.disabled = _ahPage <= 1;
  if (next) next.disabled = _ahPage >= _ahPages;
}

function _ahStatusBadge(s) {
  const map = {
    OPEN:   '<span class="badge bg-danger">OPEN</span>',
    ACK:    '<span class="badge bg-warning text-dark">ACK</span>',
    CLOSED: '<span class="badge bg-secondary">CLOSED</span>',
  };
  return map[s] || `<span class="badge bg-dark">${escapeHtml(s || '-')}</span>`;
}

function pageAlertHistory(delta) {
  const next = _ahPage + delta;
  if (next < 1 || next > _ahPages) return;
  searchAlertHistory(next);
}

function resetAlertHistory() {
  ['ah-from', 'ah-to', 'ah-ip', 'ah-text'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  ['ah-severity', 'ah-status', 'ah-type'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  const scope = document.getElementById('ah-scope');
  if (scope) scope.value = 'all';
  searchAlertHistory(1);
}

function exportAlertHistory() {
  const p = _ahParams();
  window.open('/api/alerts/history/export.csv?' + p.toString(), '_blank');
}

/* Enter 키로 검색 */
document.addEventListener('DOMContentLoaded', () => {
  ['ah-ip', 'ah-text'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('keydown', e => {
      if (e.key === 'Enter') searchAlertHistory(1);
    });
  });
});
