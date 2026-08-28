/* dashboard/13-watchlist.js — IOC 워치리스트(능동 헌팅) 패널 */
(function () {

  const WL_TYPE_META = {
    ip:     { label: 'IP',    cls: 'bg-info text-dark' },
    domain: { label: '도메인', cls: 'bg-primary' },
    hash:   { label: '해시',   cls: 'bg-secondary' },
  };

  function loadWatchlist() {
    fetch('/api/watchlist').then(r => r.json()).then(renderWatchlist).catch(() => {});
  }

  function renderWatchlist(d) {
    const items = d.items || [], s = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('wl-count', s.total ?? 0);
    set('wl-hits', (s.hit_total ?? 0).toLocaleString());
    set('wl-active', s.active_hits ?? 0);
    const tb = document.getElementById('wl-total-badge');
    if (tb) tb.textContent = (s.total ?? 0) + '개';

    const tbody = document.getElementById('wl-tbody');
    if (!tbody) return;
    tbody.innerHTML = items.length ? items.map(it => {
      const m = WL_TYPE_META[it.type] || { label: it.type, cls: 'bg-dark' };
      const hitCls = it.hits > 0 ? 'text-danger fw-bold' : 'text-muted';
      return `<tr>
        <td><span class="badge ${m.cls}">${m.label}</span></td>
        <td class="font-monospace small">${escapeHtml(it.value)}</td>
        <td class="small text-muted">${escapeHtml(it.note || '')}</td>
        <td class="small">${escapeHtml(it.added_by || '')}</td>
        <td class="small text-muted font-monospace">${escapeHtml((it.added_at || '').slice(0, 10))}</td>
        <td class="text-end ${hitCls}">${(it.hits || 0).toLocaleString()}</td>
        <td class="small text-muted font-monospace">${escapeHtml(it.last_hit || '-')}</td>
        <td class="text-end"><button class="btn btn-xs btn-outline-danger" onclick="removeWatchlist(${it.id})"><i class="fa fa-trash"></i></button></td>
      </tr>`;
    }).join('') : '<tr><td colspan="8" class="text-center text-muted py-4">등록된 IOC 가 없습니다.</td></tr>';
  }

  function addWatchlist() {
    const type = document.getElementById('wl-type')?.value;
    const value = (document.getElementById('wl-value')?.value || '').trim();
    const note = (document.getElementById('wl-note')?.value || '').trim();
    const msg = document.getElementById('wl-add-msg');
    if (!value) { if (msg) { msg.className = 'small mt-2 text-warning'; msg.textContent = '값을 입력하세요.'; } return; }
    fetch('/api/watchlist', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value, note }),
    }).then(r => r.json()).then(res => {
      if (msg) {
        msg.className = 'small mt-2 ' + (res.success ? 'text-success' : 'text-danger');
        msg.textContent = res.success ? '추가되었습니다.' : (res.error || '추가 실패');
      }
      if (res.success) {
        document.getElementById('wl-value').value = '';
        document.getElementById('wl-note').value = '';
        loadWatchlist();
      }
    }).catch(() => { if (msg) { msg.className = 'small mt-2 text-danger'; msg.textContent = '요청 실패'; } });
  }

  function removeWatchlist(id) {
    if (!confirm('이 IOC 를 워치리스트에서 삭제할까요?')) return;
    fetch('/api/watchlist/' + id, { method: 'DELETE' })
      .then(r => r.json()).then(() => loadWatchlist()).catch(() => {});
  }

  /* 실시간 워치리스트 히트 → 라이브 스트림 + 새로고침 */
  socket.on('watchlist_hit', d => {
    if (typeof pushLive === 'function') {
      pushLive('rep', 'high',
        `<b>워치리스트 히트</b> 주시 중인 IOC <span class="lv-ip">${escapeHtml(d.value)}</span> 등장`);
    }
    if (!document.getElementById('panel-watchlist')?.classList.contains('d-none')) loadWatchlist();
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    addWatchlist, loadWatchlist, removeWatchlist,
  });
})();
