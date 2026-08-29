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

  /* ── 자기 관측성 (docs/AUDIT.md 3단계 제안 B) ── */

  function loadTelemetry() {
    fetch('/api/telemetry').then(r => r.json()).then(renderTelemetry).catch(() => {});
  }

  /* 최근 표본을 막대로 그린다. 별도 시계열 저장소 없이 '언제부터 느려졌나'가 보인다. */
  function telSpark(samples, slow) {
    if (!samples || !samples.length) return '';
    const max = Math.max(...samples, 1);
    const bars = samples.map(v =>
      `<i style="height:${Math.max(1, Math.round((v / max) * 16))}px"></i>`).join('');
    return `<span class="tel-spark ${slow ? 'slow' : ''}" title="최근 ${samples.length}회">${bars}</span>`;
  }

  function renderTelemetry(d) {
    const s = d.summary || {};
    const badge = document.getElementById('tel-summary');
    if (badge) {
      badge.textContent = `지점 ${s.points || 0} · 느림 ${s.slow || 0} · 실패 ${s.failing || 0}`;
      badge.className = 'badge ms-auto ' +
        ((s.slow || s.failing || s.probe_warnings) ? 'bg-warning text-dark' : 'bg-dark');
    }

    const probes = document.getElementById('tel-probes');
    if (probes) {
      probes.innerHTML = (d.probes || []).map(p => {
        const value = p.error ? '오류' : String(p.value) + (p.unit || '');
        return `<span class="tel-probe ${p.warn ? 'warn' : ''}" title="${escapeHtml(p.error || p.name)}">`
             + `${escapeHtml(p.label)}<span class="v">${escapeHtml(value)}</span></span>`;
      }).join('');
    }

    const tbody = document.getElementById('tel-tbody');
    if (!tbody) return;
    const rows = d.points || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center p-3">아직 표본 없음</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td class="font-monospace">${escapeHtml(r.name)}</td>
        <td class="text-end font-monospace">${Number(r.calls).toLocaleString()}</td>
        <td class="text-end font-monospace">${escapeHtml(r.p50 ?? '-')}</td>
        <td class="text-end font-monospace ${r.slow ? 'tel-slow' : ''}"
            title="${r.slow ? '임계 ' + escapeHtml(r.slow_threshold_ms) + 'ms 초과'
                             : (r.warming_up ? '표본 부족 — 판정 보류' : '')}">
          ${escapeHtml(r.p95 ?? '-')}</td>
        <td class="text-end font-monospace">${escapeHtml(r.max ?? '-')}</td>
        <td>${telSpark(r.spark, r.slow)}</td>
        <td class="text-end ${r.errors ? 'tel-fail' : 'text-muted'}">${Number(r.errors)}</td>
        <td class="small text-muted">${escapeHtml(r.last_error || '')}</td>
      </tr>`).join('');
  }

  function loadHealth() {
    loadTelemetry();
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
    loadHealth, loadTelemetry, startHealthAuto, stopHealthAuto,
  });
})();
