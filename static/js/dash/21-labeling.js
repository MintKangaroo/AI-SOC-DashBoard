/* dashboard/21-labeling.js — 라벨링 큐 (정탐/오탐 확정)
   11만 건을 한 건씩 보는 대신 67개 그룹을 판정한다. */
(function () {
  function loadLabeling() {
    const only = document.getElementById('lab-real-only');
    const q = (only && only.checked) ? '&provenance=real' : '';
    fetch('/api/labeling/queue?limit=40' + q)
      .then(r => r.json()).then(renderLabeling).catch(() => {});
    fetch('/api/labeling/stats').then(r => r.json()).then(renderLabelStats).catch(() => {});
  }

  function renderLabelStats(d) {
    const box = document.getElementById('lab-stats');
    if (!box) return;
    if (!d.enabled) { box.textContent = '라벨 저장소가 비활성입니다.'; return; }
    const g = d.stats.group || {}, s = d.stats.single || {};
    box.innerHTML =
      `그룹 판정 <b>${Number(g.decisions || 0)}</b>건 → 알림 `
      + `<b>${Number(g.covers || 0).toLocaleString()}</b>건 덮음 `
      + `(정탐 ${Number(g.tp || 0)} / 오탐 ${Number(g.fp || 0)}) · `
      + `개별 판정 <b>${Number(s.decisions || 0)}</b>건`;
  }

  function renderLabeling(d) {
    const cov = document.getElementById('lab-coverage');
    if (cov) {
      const s = d.summary || {};
      const parts = [`그룹 ${Number(s.groups || 0)}개`,
                     `판정 ${Number(s.labeled_groups || 0)}개`,
                     `덮인 알림 ${Number(s.covered_alerts || 0).toLocaleString()}건 (${s.coverage_pct || 0}%)`];
      if (Number(s.excluded_synthetic || 0) > 0) {
        parts.push(`합성 ${Number(s.excluded_synthetic).toLocaleString()}건 제외됨`);
      } else if (Number(s.synthetic_alerts || 0) > 0) {
        parts.push(`이 중 합성 ${Number(s.synthetic_alerts).toLocaleString()}건 포함`);
      }
      cov.textContent = parts.join(' · ');
    }
    const box = document.getElementById('lab-groups');
    if (!box) return;
    const groups = d.groups || [];
    if (!groups.length) {
      box.innerHTML = '<div class="text-success p-2">판정할 그룹이 없습니다 — 전부 라벨됐습니다.</div>';
      return;
    }
    box.innerHTML = groups.map((g, i) => {
      const sev = Object.entries(g.severities || {})
        .map(([k, v]) => `${escapeHtml(k)} ${Number(v)}`).join(' · ');
      // 합성 알림에 붙인 '정탐' 은 생성기가 의도한 바를 확인할 뿐이다.
      // 분석가가 그걸 모르고 판정하지 않도록 카드에 못박아 둔다.
      const pv = g.provenance || {};
      const nSyn = Number(pv.synthetic || 0), nReal = Number(pv.real || 0);
      let prov = '';
      if (nSyn > 0 && nReal === 0) {
        prov = `<span class="badge bg-warning text-dark" title="${escapeHtml(pv.reason || '')}">`
             + `합성 — 정답지로 쓰지 말 것</span>`;
      } else if (nSyn > 0) {
        prov = `<span class="badge bg-warning text-dark" title="${escapeHtml(pv.reason || '')}">`
             + `혼합 실측 ${nReal.toLocaleString()} / 합성 ${nSyn.toLocaleString()}</span>`;
      } else {
        prov = '<span class="badge bg-success">합성 표지 없음</span>';
      }
      /* 출발지가 많으면 여러 주체가 같은 짓을 한 것이고, 하나면 한 호스트의 반복이다.
         그룹이 균질한지 판단하는 재료라 눈에 띄게 둔다. */
      const homo = g.unique_sources > 1
        ? `<span class="text-info">출발지 ${Number(g.unique_sources).toLocaleString()}개</span>`
        : `<span class="text-muted">단일 출발지</span>`;
      return `<div class="lab-group">
        <div class="d-flex align-items-center gap-2">
          <span class="lab-cover">${Number(g.count).toLocaleString()}건</span>
          <span class="text-muted small">(${g.coverage_pct}%)</span>
          <span class="badge bg-secondary">${escapeHtml(g.threat_type || '-')}</span>
          ${g.rule_id ? `<span class="badge bg-dark">${escapeHtml(g.rule_id)}</span>` : ''}
          ${prov}
          <span class="ms-auto small">${homo}</span>
        </div>
        <div class="desc mt-1">${escapeHtml(g.description || '')}</div>
        <div class="meta">${sev} · ${escapeHtml(g.first_seen || '')} ~ ${escapeHtml(g.last_seen || '')}</div>
        <div class="lab-actions">
          <input id="lab-reason-${i}" class="form-control form-control-sm bg-dark text-white border-secondary"
                 placeholder="판정 근거 (3자 이상 — 나중에 되짚을 수 있어야 합니다)">
          <button class="btn btn-xs btn-danger"
                  onclick="labelGroup(${i}, 'TRUE_POSITIVE')">정탐</button>
          <button class="btn btn-xs btn-success"
                  onclick="labelGroup(${i}, 'FALSE_POSITIVE')">오탐</button>
        </div>
        <div id="lab-msg-${i}" class="small mt-1"></div>
      </div>`;
    }).join('');
    window._labGroups = groups;
  }

  function labelGroup(index, verdict) {
    const g = (window._labGroups || [])[index];
    if (!g) return;
    const reason = (document.getElementById(`lab-reason-${index}`)?.value || '').trim();
    const msg = document.getElementById(`lab-msg-${index}`);
    fetch('/api/labeling/label', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: g.key, verdict, reason, covers: g.count }),
    }).then(r => r.json().then(d => ({ ok: r.ok, d }))).then(({ ok, d }) => {
      if (msg) {
        msg.innerHTML = ok
          ? `<span class="text-success">판정 완료 — 알림 ${Number(g.count).toLocaleString()}건 덮음</span>`
          : `<span class="text-danger">${escapeHtml(d.error || '판정 실패')}</span>`;
      }
      if (ok) loadLabeling();
    }).catch(() => { if (msg) msg.textContent = '판정 실패'; });
  }

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름. */
  Object.assign(window, {
    labelGroup, loadLabeling,
  });
})();
