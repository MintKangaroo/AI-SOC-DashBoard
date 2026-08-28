/* dashboard/17-siem-correlation.js — SIEM 상관관계 분석 패널 */
(function () {
  let corrFindingsBuffer = [];

  function loadSiemCorrelation() {
    fetch('/api/siem/correlation')
      .then(r => r.json())
      .then(renderSiemCorrelation)
      .catch(() => {});
  }

  const CORR_RULE_KO = {
    'R-MULTI-VECTOR': '다중 벡터',
    'R-RECON-INTRUSION': '정찰→침투',
    'R-SUSTAINED-BRUTE': '지속 브루트',
    'R-DISTRIBUTED': '분산 공격',
    'R-INTERNAL-EXFIL': '내부 자료 유출',
    'R-STAGING-EXFIL': '수집→유출',
  };

  function renderSiemCorrelation(d) {
    const stats = d.stats || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
    set('corr-total', stats.total);
    set('corr-ips', stats.active_ips);
    const badge = document.getElementById('sidebar-corr-count');
    if (badge) badge.textContent = (stats.total || 0).toLocaleString();

    // 규칙별 막대
    const byRule = stats.by_rule || {};
    const bars = Object.entries(byRule).map(([k, v]) => ({
      label: CORR_RULE_KO[k] || k, value: v, color: '#39d0d8',
    }));
    if (typeof svgHBars === 'function') svgHBars('corr-rule-bars', bars, '건');

    // 규칙 정의
    const rulesBox = document.getElementById('corr-rules');
    if (rulesBox) {
      rulesBox.innerHTML = (d.rules || []).map(r => `
        <div class="p-2 border-bottom border-secondary">
          <div class="small fw-bold" style="color:#e6edf3">
            <span class="badge bg-dark border border-secondary font-monospace" style="font-size:8px">${escapeHtml(r.id)}</span>
            ${escapeHtml(r.name)}
            <span class="badge bg-secondary ms-1" style="font-size:9px">${(byRule[r.id] || 0)}건</span>
          </div>
          <div class="small text-muted" style="font-size:10px">${escapeHtml(r.desc)}</div>
        </div>`).join('');
    }

    corrFindingsBuffer = d.findings || [];
    renderCorrFindings();
  }

  function corrFindingRow(f) {
    const sevCls = f.severity === 'CRITICAL' ? 'bg-danger' : 'bg-orange';
    return `
      <tr style="background:rgba(56,189,248,.05)">
        <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(f.timestamp)}</td>
        <td class="small"><span class="badge bg-info text-dark" style="font-size:9px">${escapeHtml(CORR_RULE_KO[f.rule] || f.rule)}</span></td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(f.ip)}</td>
        <td class="small"><span class="badge ${sevCls}" style="font-size:9px">${escapeHtml(f.severity)}</span></td>
        <td class="small" style="color:#cdd9e5">${escapeHtml(f.summary)}
          ${f.dst_ip ? `<div class="text-muted font-monospace" style="font-size:10px">목적지 ${escapeHtml(f.dst_ip)}${f.bytes_out ? ` · ${(Number(f.bytes_out)/1e6).toFixed(1)}MB` : ''}</div>` : ''}</td>
      </tr>`;
  }

  function renderCorrFindings() {
    const tb = document.getElementById('corr-findings');
    if (!tb) return;
    tb.innerHTML = corrFindingsBuffer.length
      ? corrFindingsBuffer.slice(0, 100).map(corrFindingRow).join('')
      : '<tr><td colspan="5" class="text-muted text-center p-3">아직 상관 탐지가 없습니다.</td></tr>';
  }

  socket.on('siem_correlation', f => {
    corrFindingsBuffer.unshift(f);
    while (corrFindingsBuffer.length > 200) corrFindingsBuffer.pop();
    const badge = document.getElementById('sidebar-corr-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g, '')) || 0) + 1).toLocaleString();
    pushLive('alert', f.severity,
      `<b>상관관계 ${escapeHtml(CORR_RULE_KO[f.rule] || f.rule)}</b> <span class="lv-ip">${escapeHtml(f.ip)}</span> ${escapeHtml(f.summary)}`);
    const panel = document.getElementById('panel-siem-correlation');
    if (panel && !panel.classList.contains('d-none')) renderCorrFindings();
  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadSiemCorrelation,
  });
})();
