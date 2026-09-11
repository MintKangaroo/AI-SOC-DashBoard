/* dashboard/14-campaigns.js — 킬체인 상관관계(공격 캠페인) 패널 */
(function () {

  function loadCampaigns() {
    const hours = document.getElementById('camp-hours')?.value || 24;
    fetch('/api/correlation/campaigns?hours=' + hours)
      .then(r => r.json()).then(renderCampaigns).catch(() => {});
  }

  function renderCampaigns(d) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('camp-total', d.total ?? 0);
    set('camp-multi', d.multistage ?? 0);
    set('camp-window', d.window_minutes ?? '-');
    const tb = document.getElementById('camp-total-badge');
    if (tb) tb.textContent = (d.total ?? 0) + '건';

    const list = document.getElementById('camp-list');
    if (!list) return;
    const camps = d.campaigns || [];
    if (!camps.length) {
      list.innerHTML = '<div class="card-panel text-center text-muted py-4">해당 기간에 상관관계로 묶인 캠페인이 없습니다.</div>';
      return;
    }
    reconcileList(list, camps, c => [c.src_ip,c.start,c.provenance?.state].join(':'), campaignCard, {sig:c => JSON.stringify(c)});
  }

  function campaignCard(c) {
    const sev = sevBadge(c.severity);
    const multi = c.stage_count >= 2;
    const border = 'var(--border)';
    // 킬체인 진행: 각 단계를 화살표로 연결
    const chain = (c.stages || []).map((s, i) => {
      const arrow = i > 0 ? '<span class="camp-arrow">→</span>' : '';
      const tts = (s.labels || []).join(', ');
      return `${arrow}<span class="camp-stage" title="${escapeHtml(s.tactic)} — ${escapeHtml(tts)}">
        <span class="camp-stage-tac">${escapeHtml(s.tactic_ko)}</span>
        <span class="camp-stage-tt">${escapeHtml(tts)}</span><small>${escapeHtml(s.first_seen || '')}</small>
      </span>`;
    }).join('');

    return `
      <div class="card-panel mb-2"
           style="border-color:color-mix(in srgb, ${border} 45%, var(--border));
                  background:linear-gradient(180deg, color-mix(in srgb, ${border} 6%, transparent), transparent), var(--bg-card)">
        <div class="d-flex align-items-center flex-wrap gap-2 mb-2">
          ${SOCUI.entity(c.src_ip)} ${SOCUI.provenance(c)}
          ${sev}
          ${multi ? `<span class="badge bg-danger">다단계 ${c.stage_count}단계</span>` : ''}
          <span class="small text-muted">알림 ${c.alert_count}건 · ${escapeHtml(c.start)} ~ ${escapeHtml((c.end||'').slice(11))} (${c.duration_min}분)</span>
        </div>
        <div class="camp-chain">${chain}</div>
        <details class="camp-evidence"><summary>구성 알림 증거 조사 · ${c.alert_count}건</summary><p class="text-muted small">단계는 MITRE 전술 순서로 정렬한 것이지 인과 관계의 증명이 아닙니다. 기록된 최초 관측 시각은 위에 표시됩니다. 같은 출발지와 시간은 상관관계만 뜻합니다.</p><div class="d-flex flex-wrap gap-2">${(c.alert_ids || []).map(id => `<button class="btn btn-xs btn-outline-secondary" ${act('consoleOpenInvestigation',[id])}>알림 #${id}</button>`).join('')}</div></details>
      </div>`;
  }

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadCampaigns,
  });
})();
