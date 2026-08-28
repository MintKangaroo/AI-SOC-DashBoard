/* dashboard/10-health.js — 모듈 헬스(전 서비스 가동/모드) 패널 */
(function () {

  let _healthTimer = null;

  const HEALTH_MODE_META = {
    real: { label: '실측',  cls: 'bg-success',                       dot: 'var(--green)'  },
    live: { label: '상시',  cls: '',                                 dot: 'var(--cyan)'   },
    demo: { label: '데모',  cls: 'bg-warning text-dark',             dot: 'var(--yellow)' },
    off:  { label: '비활성', cls: 'bg-secondary',                     dot: 'var(--text-muted)' },
    down: { label: '중단',  cls: 'bg-danger',                        dot: 'var(--red)'    },
  };

  function _healthModeBadge(mode) {
    const m = HEALTH_MODE_META[mode] || HEALTH_MODE_META.demo;
    if (mode === 'live') {
      return `<span class="badge" style="background:var(--cyan);color:#001417">${m.label}</span>`;
    }
    return `<span class="badge ${m.cls}">${m.label}</span>`;
  }

  function loadHealth() {
    fetch('/api/system/health')
      .then(r => r.json())
      .then(renderHealth)
      .catch(() => {});
  }

  function renderHealth(d) {
    const sum = d.summary || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('hs-total', sum.total ?? '-');
    set('hs-running', sum.running ?? '-');
    set('hs-real', sum.real ?? '-');
    set('hs-demo', sum.demo ?? '-');
    set('hs-off', sum.off ?? '-');
    set('hs-down', sum.down ?? '-');

    const demoBadge = document.getElementById('health-demo-badge');
    if (demoBadge) {
      demoBadge.textContent = sum.demo_mode ? 'DEMO_MODE=True' : 'DEMO_MODE=False';
      demoBadge.style.background = sum.demo_mode ? 'var(--yellow)' : 'var(--green)';
      demoBadge.style.color = '#001417';
    }

    // 사이드바 배지: 중단 모듈 수(있을 때만 강조)
    const sb = document.getElementById('sidebar-health-count');
    if (sb) {
      sb.textContent = sum.down || 0;
      sb.className = 'badge ms-auto ' + ((sum.down || 0) > 0 ? 'bg-danger' : 'bg-secondary');
    }

    // 카테고리별 그룹핑
    const groups = {};
    (d.modules || []).forEach(m => { (groups[m.category] ??= []).push(m); });

    const html = Object.entries(groups).map(([cat, mods]) => `
      <div class="mb-3">
        <div class="small text-muted mb-1" style="letter-spacing:.05em">
          ${escapeHtml(cat)} <span class="text-secondary">(${mods.length})</span>
        </div>
        <div class="card-panel p-0">
          <table class="table table-dark table-sm table-hover mb-0 align-middle">
            <tbody>
              ${mods.map(_healthRow).join('')}
            </tbody>
          </table>
        </div>
      </div>`).join('');

    const container = document.getElementById('health-groups');
    if (container) container.innerHTML = html;
  }

  function _healthRow(m) {
    const meta = HEALTH_MODE_META[m.mode] || HEALTH_MODE_META.demo;
    const runIcon = m.running
      ? '<i class="fa fa-circle-check text-success" title="가동 중"></i>'
      : '<i class="fa fa-circle-xmark text-danger" title="중단"></i>';
    return `
      <tr>
        <td style="width:34px" class="text-center">
          <span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${meta.dot}"></span>
        </td>
        <td style="width:220px">${escapeHtml(m.label)}</td>
        <td style="width:70px">${_healthModeBadge(m.mode)}</td>
        <td class="text-muted small">${escapeHtml(m.detail || '')}</td>
        <td style="width:40px" class="text-center">${runIcon}</td>
      </tr>`;
  }

  /* 패널 진입 시: 즉시 로드 + 자동 갱신 타이머 관리 */
  function startHealthAuto() {
    stopHealthAuto();
    const on = document.getElementById('health-auto')?.checked;
    if (on) _healthTimer = setInterval(loadHealth, 10000);
  }
  function stopHealthAuto() {
    if (_healthTimer) { clearInterval(_healthTimer); _healthTimer = null; }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const chk = document.getElementById('health-auto');
    if (chk) chk.addEventListener('change', startHealthAuto);
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadHealth, startHealthAuto, stopHealthAuto,
  });
})();
