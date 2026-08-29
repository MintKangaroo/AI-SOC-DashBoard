/* dashboard/19-yara.js — YARA 악성코드 스캐너 패널
   해시 대조가 못 잡는 변종을 내용 패턴으로 잡는다. */
(function () {
  function loadYara() {
    fetch('/api/yara/status').then(r => r.json()).then(renderYara).catch(() => {});
  }

  function sevBadgeYara(sev) {
    const map = { CRITICAL: 'bg-danger', HIGH: 'bg-warning text-dark',
                  MEDIUM: 'bg-info text-dark', LOW: 'bg-secondary' };
    return `<span class="badge ${map[sev] || 'bg-secondary'}">${escapeHtml(sev || '-')}</span>`;
  }

  function renderYara(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('yara-rules', stats.rules_loaded || 0);
    set('yara-scanned', (stats.files_scanned || 0).toLocaleString());
    set('yara-matches', stats.matches || 0);

    const badge = document.getElementById('yara-mode-badge');
    if (badge) {
      const on = stats.enabled && d.running;
      badge.textContent = on ? '실동작' : (stats.enabled ? '대기' : 'yara-python 미설치');
      badge.style.background = on ? '#238636' : '#6e7681';
    }
    const limits = d.limits || {};
    set('yara-limits', `${limits.max_file_mb ?? '-'}MB · ${limits.timeout ?? '-'}s`);

    const sidebar = document.getElementById('sidebar-yara-count');
    if (sidebar) sidebar.textContent = stats.rules_loaded || 0;

    const tbody = document.getElementById('yara-rules-tbody');
    if (tbody) {
      const rules = d.rules || [];
      tbody.innerHTML = rules.length ? rules.map(r => `
        <tr>
          <td class="font-monospace small">${escapeHtml(r.name)}</td>
          <td>${sevBadgeYara(r.severity)}</td>
          <td class="font-monospace small">${escapeHtml(r.mitre || '-')}</td>
          <td class="small" style="color:#e6edf3">${escapeHtml(r.description || '')}</td>
        </tr>`).join('')
        : `<tr><td colspan="4" class="text-muted text-center p-3">${
             escapeHtml(d.reason || '로드된 룰 없음')}</td></tr>`;
    }

    const recent = document.getElementById('yara-recent');
    if (recent) {
      const rows = d.matches || [];
      recent.innerHTML = rows.length ? rows.map(m => `
        <div class="border-bottom border-secondary py-1">
          ${sevBadgeYara(m.severity)}
          <span class="font-monospace ms-1">${escapeHtml(m.path)}</span>
          <div class="text-muted">${escapeHtml((m.matches || []).map(x => x.rule).join(', '))}
            · ${escapeHtml(m.scanned_at || '')}</div>
        </div>`).join('') : '아직 탐지 없음';
    }
  }

  function runYaraScan() {
    const input = document.getElementById('yara-path');
    const out = document.getElementById('yara-scan-result');
    const path = (input && input.value || '').trim();
    if (!path) { if (out) out.textContent = '경로를 입력하세요.'; return; }
    if (out) out.textContent = '스캔 중…';
    fetch('/api/yara/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    }).then(r => r.json()).then(d => {
      if (!out) return;
      if (d.error) { out.innerHTML = `<span class="text-danger">${escapeHtml(d.error)}</span>`; return; }
      if (d.results !== undefined) {          // 디렉터리 스캔
        out.innerHTML = `파일 ${Number(d.files_scanned).toLocaleString()}개 스캔 · `
          + `<b class="${d.matched_files ? 'text-danger' : 'text-success'}">매치 ${Number(d.matched_files)}개</b>`
          + (d.truncated ? ` <span class="text-warning">(상한 ${Number(d.max_files)}개에서 중단)</span>` : '')
          + (d.results || []).map(r => `<div class="mt-1">${sevBadgeYara(r.severity)}
              <span class="font-monospace">${escapeHtml(r.path)}</span> —
              ${escapeHtml((r.matches || []).map(m => String(m.rule)).join(', '))}</div>`).join('');
      } else {                                 // 단일 파일
        out.innerHTML = d.matches && d.matches.length
          ? `${sevBadgeYara(d.severity)} <b class="text-danger">탐지</b> — `
            + escapeHtml(d.matches.map(m => m.rule + '(' + (m.mitre || '-') + ')').join(', '))
          : `<span class="text-success">매치 없음</span>`
            + (d.skipped ? ` <span class="text-warning">${escapeHtml(d.error || '')}</span>` : '');
      }
      loadYara();
    }).catch(() => { if (out) out.textContent = '스캔 실패'; });
  }

  function reloadYara() {
    fetch('/api/yara/reload', { method: 'POST' })
      .then(r => r.json()).then(() => loadYara()).catch(() => {});
  }

  socket.on('yara_match', m => {
    if (typeof pushLive === 'function') {
      pushLive('alert', m.severity,
        `<b style="color:#f85149">YARA 탐지</b> ${escapeHtml((m.rules || []).join(', '))} `
        + `<span class="lv-ip">${escapeHtml(m.path)}</span>`);
    }
    if (isPanelVisible('yara') && !document.hidden) loadYara();
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름. */
  Object.assign(window, {
    loadYara, reloadYara, runYaraScan,
  });
})();
