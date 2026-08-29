/* dashboard/20-hunt.js — 위협 헌팅 콘솔 (저장된 쿼리)
   헌팅은 반복 행위다. 조건을 저장하고, 지난번 이후 새로 걸린 것만 세고,
   찾은 지표를 워치리스트로 올린다. */
(function () {
  let _hunts = [];

  function loadHunts() {
    fetch('/api/hunts').then(r => r.json()).then(d => {
      _hunts = d.hunts || [];
      renderHuntList();
    }).catch(() => {});
  }

  function renderHuntList() {
    const box = document.getElementById('hunt-list');
    const count = document.getElementById('hunt-count');
    const side = document.getElementById('sidebar-hunt-count');
    if (count) count.textContent = _hunts.length;
    if (side) side.textContent = _hunts.length;
    if (!box) return;
    if (!_hunts.length) {
      box.innerHTML = '<div class="text-muted p-2">저장된 헌팅이 없습니다.</div>';
      return;
    }
    box.innerHTML = _hunts.map(h => {
      const cond = Object.entries(h.filters || {})
        .filter(([k]) => k !== 'scope')
        .map(([k, v]) => `${escapeHtml(k)}=${escapeHtml(v)}`).join(' · ');
      const last = h.last_run_at
        ? `마지막 ${escapeHtml(h.last_run_at)} · ${Number(h.last_total).toLocaleString()}건 · ${Number(h.run_count)}회 실행`
        : '아직 실행 안 함';
      return `<div class="border-bottom border-secondary py-2">
        <div class="d-flex align-items-center gap-2">
          <b style="color:#e6edf3">${escapeHtml(h.name)}</b>
          <button class="btn btn-xs btn-purple ms-auto" onclick="runHunt(${Number(h.id)})">실행</button>
          <button class="btn btn-xs btn-outline-secondary" onclick="deleteHunt(${Number(h.id)})"
                  title="삭제">&times;</button>
        </div>
        <div class="small" style="color:#8b949e">${escapeHtml(h.description || '')}</div>
        <div class="small font-monospace" style="color:#58a6ff">${cond}</div>
        <div class="small text-muted">${last}</div>
      </div>`;
    }).join('');
  }

  function runHunt(id) {
    const tbody = document.getElementById('hunt-result-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">사냥 중…</td></tr>';
    fetch(`/api/hunts/${Number(id)}/run?limit=200`)
      .then(r => r.json()).then(d => { renderHuntResult(d); loadHunts(); })
      .catch(() => { if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger py-3">실행 실패</td></tr>'; });
  }

  function renderHuntResult(d) {
    const badge = document.getElementById('hunt-result-badge');
    if (badge) {
      if (d.error) {
        badge.textContent = '오류';
        badge.className = 'badge bg-danger ms-2';
      } else {
        /* 첫 실행은 전부가 '새것'이라 델타가 의미 없다 — 그걸 그대로 말한다. */
        badge.textContent = d.first_run
          ? `${Number(d.total).toLocaleString()}건 (첫 실행 — 기준선 설정)`
          : `${Number(d.total).toLocaleString()}건 · 새로 ${Number(d.new_count)}건`;
        badge.className = 'badge ms-2 ' + (d.new_count && !d.first_run ? 'bg-warning text-dark' : 'bg-dark');
      }
    }

    const promote = document.getElementById('hunt-promote');
    if (promote) {
      const tops = d.top_sources || [];
      promote.innerHTML = tops.length
        ? '반복 출발지: ' + tops.map(t =>
            `<span class="badge bg-dark border border-secondary me-1">${escapeHtml(t.ip)}
             <span class="text-muted">${Number(t.count)}</span>
             <a href="javascript:;" class="ms-1 text-info"
                onclick="promoteHunt('${escapeHtml(t.ip)}')" title="워치리스트로 승격">+</a></span>`).join('')
        : '';
    }

    const tbody = document.getElementById('hunt-result-tbody');
    if (!tbody) return;
    if (d.error) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">${escapeHtml(d.error)}</td></tr>`;
      return;
    }
    const rows = d.results || [];
    const isNew = new Set(d.first_run ? [] : (d.new_ids || []));
    tbody.innerHTML = rows.length ? rows.map(a => `
      <tr${isNew.has(a.id) ? ' style="background:rgba(210,153,34,.10)"' : ''}>
        <td class="font-monospace small text-nowrap">${escapeHtml(a.timestamp || '')}
          ${isNew.has(a.id) ? '<span class="badge bg-warning text-dark ms-1">NEW</span>' : ''}</td>
        <td>${sevBadge(a.severity)}</td>
        <td class="small">${escapeHtml(a.threat_label || a.threat_type || '')}</td>
        <td class="font-monospace small">${escapeHtml(a.src_ip || '')}</td>
        <td class="small">${escapeHtml(a.description || '')}</td>
      </tr>`).join('')
      : '<tr><td colspan="5" class="text-center text-muted py-3">걸린 것이 없습니다 — 그것도 정보입니다.</td></tr>';
  }

  function createHunt() {
    const val = id => (document.getElementById(id)?.value || '').trim();
    const filters = {};
    if (val('hunt-sev')) filters.severity = val('hunt-sev');
    if (val('hunt-ip')) filters.ip = val('hunt-ip');
    if (val('hunt-text')) filters.text = val('hunt-text');
    if (val('hunt-verdict')) filters.verdict = val('hunt-verdict');
    const msg = document.getElementById('hunt-create-msg');
    fetch('/api/hunts', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: val('hunt-name'), description: val('hunt-desc'), filters }),
    }).then(r => r.json().then(d => ({ ok: r.ok, d }))).then(({ ok, d }) => {
      if (msg) msg.innerHTML = ok
        ? `<span class="text-success">저장했습니다: ${escapeHtml(d.name)}</span>`
        : `<span class="text-danger">${escapeHtml(d.error || '저장 실패')}</span>`;
      if (ok) {
        ['hunt-name', 'hunt-desc', 'hunt-ip', 'hunt-text'].forEach(id => {
          const el = document.getElementById(id); if (el) el.value = '';
        });
        loadHunts();
      }
    }).catch(() => { if (msg) msg.textContent = '저장 실패'; });
  }

  function deleteHunt(id) {
    if (!confirm('이 헌팅을 삭제할까요?')) return;
    fetch(`/api/hunts/${Number(id)}`, { method: 'DELETE' })
      .then(() => loadHunts()).catch(() => {});
  }

  function promoteHunt(ip) {
    fetch('/api/hunts/promote', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: ip, type: 'ip', note: '헌팅에서 승격' }),
    }).then(r => r.json()).then(d => {
      const box = document.getElementById('hunt-promote');
      if (box) {
        const note = document.createElement('div');
        note.className = d.ok ? 'text-success small mt-1' : 'text-danger small mt-1';
        // textContent 라 이스케이프가 필요 없다. 템플릿 리터럴을 피해
        // '서버 문자열이 HTML 로 간다'는 검사에 걸리지 않게 한다.
        note.textContent = d.ok ? ip + ' 워치리스트에 추가했습니다.'
                                : (d.error || '승격 실패');
        box.appendChild(note);
      }
    }).catch(() => {});
  }

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름. */
  Object.assign(window, {
    createHunt, deleteHunt, loadHunts, promoteHunt, runHunt,
  });
})();
