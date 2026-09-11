/* Durable queue: server filters, explicit refresh, snapshot bulk actions. */
(function () {
  let queueRecords = [];
  let queuePage = 0;
  let queueVersion = 0;
  let queueNewEvents = 0;
  const queueSelection = new Set();
  const queueHiddenColumns = new Set();
  const queueInputFields = ['search','severity','status','origin','order','source','rule','confidence'];

  function queueResizeColumns() {
    document.querySelectorAll('#console-queue-table th').forEach((th,index) => {
      if (!index) return;
      const handle = document.createElement('span');
      handle.className = 'column-resize-handle'; handle.tabIndex = 0;
      handle.setAttribute('role','separator'); handle.setAttribute('aria-orientation','vertical');
      handle.setAttribute('aria-label',th.textContent.trim() + ' 열 너비 조절');
      const size = value => { const width = Math.min(600,Math.max(80,value)); th.style.width = width + 'px'; th.style.minWidth = width + 'px'; handle.setAttribute('aria-valuenow',String(Math.round(width))); };
      handle.setAttribute('aria-valuemin','80'); handle.setAttribute('aria-valuemax','600');
      handle.setAttribute('aria-valuenow',String(Math.min(600,Math.max(80,Math.round(th.getBoundingClientRect().width)))));
      handle.addEventListener('pointerdown',event => {
        event.preventDefault(); event.stopPropagation();
        const start = event.clientX, width = th.getBoundingClientRect().width;
        handle.setPointerCapture(event.pointerId);
        const move = ev => size(width + ev.clientX - start);
        const stop = () => { handle.removeEventListener('pointermove',move); handle.removeEventListener('pointerup',stop); handle.removeEventListener('pointercancel',stop); };
        handle.addEventListener('pointermove',move); handle.addEventListener('pointerup',stop); handle.addEventListener('pointercancel',stop);
      });
      handle.addEventListener('keydown',event => { if (['ArrowLeft','ArrowRight'].includes(event.key)) { event.preventDefault(); size(th.getBoundingClientRect().width + (event.key === 'ArrowLeft' ? -16 : 16)); } });
      th.appendChild(handle);
    });
  }
  function queueParameters() {
    const values = {};
    queueInputFields.forEach(key => { values[key === 'search' ? 'q' : key] = document.getElementById('queue-' + key)?.value || ''; });
    values.hours = SOCUI.hours; values.limit = 50; values.offset = queuePage * 50;
    return new URLSearchParams(values);
  }
  async function consoleLoadQueue(reset) {
    if (!document.getElementById('console-queue-rows')) return;
    if (reset) queuePage = 0;
    const version = ++queueVersion;
    const box = document.getElementById('console-queue-rows');
    box.setAttribute('aria-busy','true');
    try {
      const data = await SOCUI.request('/api/console/alerts?' + queueParameters());
      if (version !== queueVersion) return;
      queueRecords = data.alerts;
      const visible = new Set(queueRecords.map(a => a.id));
      [...queueSelection].forEach(id => { if (!visible.has(id)) queueSelection.delete(id); });
      if (!queueRecords.length) box.innerHTML = '<tr><td colspan="11"><div class="console-empty">조건에 맞는 알림이 없습니다. 기간을 바꾸거나 센서 가시성을 확인하세요.</div></td></tr>';
      else reconcileList(box, queueRecords, a => a.id, queueRow, {sig:a => JSON.stringify(a)});
      document.getElementById('queue-pagination').textContent = `${SOCUI.number(data.total)}건 일치 · ${data.alerts.length ? data.offset + 1 : 0}–${data.offset + data.alerts.length} · 최근 ${SOCUI.hours}시간 · 아카이브 포함`;
      document.getElementById('queue-prev').disabled = queuePage === 0;
      document.getElementById('queue-next').disabled = data.offset + data.alerts.length >= data.total;
      queueNewEvents = 0;
      document.getElementById('queue-new-events').textContent = '실시간 · 행 고정';
      queueSyncSelection();
      queueApplyColumns();
    } catch (error) { if (version === queueVersion) document.getElementById('queue-pagination').textContent = '큐가 최신이 아닐 수 있음: ' + error.message; }
    finally { if (version === queueVersion) box.removeAttribute('aria-busy'); }
  }
  function queueRow(a) {
    const d = a.details || {};
    const rule = d.rule_id || d.sid || d.rule || d.signature_id;
    const technique = d.mitre || (Array.isArray(d.mitre_techniques) ? d.mitre_techniques.join(', ') : null);
    return `<tr class="queue-table-row" data-alert-id="${a.id}" tabindex="0" aria-label="알림 ${a.id}: ${escapeHtml(a.threat_type)}" ${act('consoleOpenInvestigation',[a.id])}><td><input type="checkbox" aria-label="알림 ${a.id} 선택" data-queue-select="${a.id}" ${a.archived ? 'disabled title="아카이브 증거는 읽기 전용"' : ''} ${act('consoleSelectAlert',[a.id,'@el'])} data-stop/></td><td>${sevBadge(a.severity)}</td><td><span class="detection-title">${escapeHtml(a.description || a.threat_type)}</span><span class="detection-meta">#${a.id} · ${SOCUI.entity(a.src_ip)} ${d.dedup?.count > 1 ? ' · ×' + Number(d.dedup.count) : ''}</span></td><td class="col-confidence">${SOCUI.confidence(a)}</td><td>${escapeHtml(a.status)}${a.archived ? '<small class="d-block text-muted">아카이브</small>' : ''}</td><td>${SOCUI.provenance(a)}</td><td class="col-source">${escapeHtml(d.source || d.siem_source || d.sensor || '—')}</td><td class="col-rule">${rule ? SOCUI.entity(rule) : '—'}</td><td class="col-technique">${technique ? SOCUI.entity(technique) : '—'}</td><td class="col-assignee">${escapeHtml(a.assignee || '미배정')}</td><td class="text-nowrap">${escapeHtml(a.timestamp || '—')}</td></tr>`;
  }
  function consoleQueuePage(delta) { queuePage = Math.max(0,queuePage + delta); consoleLoadQueue(); }
  function consoleQueueView(view) {
    SOCUI.navigate('alerts');
    const status = {open:'OPEN',critical:'OPEN',high:'OPEN',ack:'ACK',all:''}[view] ?? 'OPEN';
    document.getElementById('queue-status').value = status;
    document.getElementById('queue-severity').value = view === 'critical' ? 'CRITICAL' : view === 'high' ? 'HIGH' : '';
    document.querySelectorAll('.queue-views button').forEach(button => button.classList.toggle('active', button.dataset.args === JSON.stringify([view])));
    consoleLoadQueue(true);
  }
  function consoleSelectAlert(id, checkbox) {
    if (checkbox.checked) queueSelection.add(id); else queueSelection.delete(id);
    queueSyncSelection();
  }
  function consoleSelectAll(checkbox) {
    queueRecords.filter(a => !a.archived).forEach(a => { if (checkbox.checked) queueSelection.add(a.id); else queueSelection.delete(a.id); });
    queueSyncSelection();
  }
  function queueSyncSelection() {
    document.querySelectorAll('[data-queue-select]').forEach(box => {
      box.checked = queueSelection.has(Number(box.dataset.queueSelect));
      box.closest('tr').setAttribute('aria-selected',String(box.checked));
    });
    const label = document.getElementById('queue-selected');
    if (label) label.textContent = `${queueSelection.size}건 선택`;
    const all = document.getElementById('queue-select-all');
    if (all) { const count = queueRecords.filter(a => !a.archived).length; all.checked = !!count && queueSelection.size === count; all.indeterminate = queueSelection.size > 0 && queueSelection.size < count; }
  }
  function consoleClearSelection(ids) { ids.forEach(id => queueSelection.delete(id)); queueSyncSelection(); }
  function consoleBulkAction(action) { consoleAnalystAction(action,[...queueSelection]); }
  function consoleToggleColumn(column, checkbox) { if (checkbox.checked) queueHiddenColumns.delete(column); else queueHiddenColumns.add(column); queueApplyColumns(); }
  function queueApplyColumns() {
    ['confidence','source','rule','technique','assignee'].forEach(col => document.querySelectorAll('#console-queue-table .col-' + col).forEach(el => { el.hidden = queueHiddenColumns.has(col); }));
  }
  function queueSavedViews() { try { const v = JSON.parse(localStorage.getItem('trace.queue.views') || '[]'); return Array.isArray(v) ? v.slice(0,20) : []; } catch { return []; } }
  function queueRefreshViews() {
    const select = document.getElementById('queue-saved');
    if (select) select.innerHTML = '<option value="">저장된 보기 (이 브라우저)</option>' + queueSavedViews().map((view,i) => `<option value="${i}">${escapeHtml(view.name)}</option>`).join('');
  }
  function consoleSaveView() {
    const views = queueSavedViews();
    const filters = Object.fromEntries(queueParameters());
    const name = [filters.severity || '전체 심각도',filters.status || '전체 상태',filters.origin,filters.q].filter(Boolean).join(' · ').slice(0,100);
    try { localStorage.setItem('trace.queue.views',JSON.stringify([{name,filters},...views.filter(v => v.name !== name)].slice(0,20))); queueRefreshViews(); SOCUI.notify('보기를 이 브라우저에 저장했습니다.'); }
    catch { SOCUI.notify('브라우저 저장소를 쓸 수 없어 보기를 저장하지 못했습니다.'); }
  }
  function consoleRestoreView(select) {
    if (select.value === '') return;
    const view = queueSavedViews()[Number(select.value)];
    if (!view?.filters) return;
    queueInputFields.forEach(field => { const input = document.getElementById('queue-' + field); if (input) input.value = view.filters[field === 'search' ? 'q' : field] || ''; });
    consoleLoadQueue(true);
  }
  function consoleShowSuppressed() {
    SOCUI.navigate('alerts');
    const panel = document.getElementById('console-suppressed');
    if (panel) { panel.open = true; panel.scrollIntoView({block:'start'}); }
    loadSuppressed(1);
  }
  function consoleQueueIncoming() {
    queueNewEvents++;
    const button = document.getElementById('queue-new-events');
    if (button) button.textContent = `+${SOCUI.number(queueNewEvents)}건 새 알림 · 새로고침`;
  }
  onPanelReady('alerts', () => { queueRefreshViews(); queueResizeColumns(); });
  document.addEventListener('keydown',event => {
    if (event.defaultPrevented) return; // Core handles role=button rows once.
    const row = event.target.closest?.('tr[data-alert-id]');
    if (!row || event.target !== row) return;
    if (event.key === 'Enter') { event.preventDefault(); consoleOpenInvestigation(Number(row.dataset.alertId)); }
    if (['ArrowDown','ArrowUp'].includes(event.key)) { event.preventDefault(); (event.key === 'ArrowDown' ? row.nextElementSibling : row.previousElementSibling)?.focus(); }
  });
  Object.assign(window, {consoleBulkAction, consoleClearSelection, consoleLoadQueue, consoleQueueIncoming,
    consoleQueuePage, consoleQueueView, consoleRestoreView, consoleSaveView, consoleSelectAlert,
    consoleSelectAll, consoleShowSuppressed, consoleToggleColumn});
})();
