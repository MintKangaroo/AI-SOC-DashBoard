/* dashboard/11-metrics.js — SOC 운영 지표(추세·MTTR·히트맵) 패널 */
(function () {

  function loadMetrics() {
    const days = document.getElementById('metrics-days')?.value || 14;
    fetch('/api/metrics/soc?days=' + days)
      .then(r => r.json())
      .then(d => { if (d.labels) window._threatTypeLabels = d.labels; renderMetrics(d); })
      .catch(() => {});
    loadRetention();
  }

  function loadRetention() {
    fetch('/api/alerts/retention').then(r => r.json()).then(d => {
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('mr-live', (d.live ?? 0).toLocaleString());
      set('mr-archived', (d.archived ?? 0).toLocaleString());
      set('mr-oldest', d.oldest || '-');
      const p = d.policy || {};
      set('mr-days', p.live_days ?? '-');
      set('mr-archive-days', p.archive_days ?? '-');
      set('mr-audit-days', p.audit_days ?? '-');
      set('mr-file-days', p.file_days ?? '-');
      set('mr-preview-archive', (d.to_archive ?? 0).toLocaleString());
      set('mr-preview-delete', (d.destructive_total ?? 0).toLocaleString());
      const lbl = document.getElementById('mr-archive-label');
      if (lbl) lbl.textContent = '정책 지금 실행';
      const hist = document.getElementById('mr-history');
      if (hist) hist.innerHTML = (d.history || []).slice(0, 5).map(h =>
        `<div>${escapeHtml(h.ts)} · ${escapeHtml(h.trigger)} · 아카이브 ${h.archived} · 삭제 ${h.archive_deleted + h.audit_deleted + h.files_deleted}</div>`
      ).join('') || '아직 실행 이력 없음';
    }).catch(() => {});
  }

  function runArchive() {
    const msg = document.getElementById('mr-msg');
    const arch = document.getElementById('mr-preview-archive')?.textContent || '0';
    const del = document.getElementById('mr-preview-delete')?.textContent || '0';
    if (!confirm(`미리보기: 알림 ${arch}건 아카이브, 장기 보존 만료 ${del}건 영구삭제\n계속할까요?`)) return;
    fetch('/api/alerts/retention/run', { method: 'POST', headers: {'Content-Type':'application/json'}, body:'{}' })
    .then(async r => ({status:r.status, body:await r.json()})).then(({status, body:d}) => {
      if (status === 409 && d.requires_confirmation) {
        if (!confirm(`${d.error}\n정말 실행할까요?`)) return;
        return fetch('/api/alerts/retention/run', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({confirm_large:true})})
          .then(r => r.json()).then(showRetentionResult);
      }
      showRetentionResult(d);
    }).catch(() => { if (msg) { msg.className = 'small mt-2 text-danger'; msg.textContent = '요청 실패'; } });

    function showRetentionResult(d) {
      if (msg) {
        msg.className = 'small mt-2 ' + (d.success ? 'text-success' : 'text-danger');
        const r = d.result || {};
        msg.textContent = d.success ? `아카이브 ${(r.archived || 0).toLocaleString()}건 · 영구삭제 ${((r.archive_deleted||0)+(r.audit_deleted||0)+(r.files_deleted||0)).toLocaleString()}건` : (d.error || '실패');
      }
      loadRetention();
    }
  }

  function renderMetrics(d) {
    const k = d.kpi || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('mk-total', (k.total_alerts || 0).toLocaleString());
    set('mk-mttr', k.mttr || '-');
    set('mk-mtta', k.mtta || '-');
    set('mk-close', (k.close_rate ?? 0) + '%');
    set('mk-fp', k.fp_rate == null ? '-' : k.fp_rate + '%');
    set('mk-inc', `${k.incidents_opened || 0} / ${k.incidents_resolved || 0}`);

    renderDailyBars('metrics-daily', d.by_day || []);
    renderHeatmap('metrics-heatmap', d.heatmap || []);
    svgHBars('metrics-types', (d.top_types || []).map(t => ({
      label: threatLabel(t.type), value: t.count, color: 'var(--red)'
    })));
    svgHBars('metrics-attackers', (d.top_ips || []).map(t => ({
      label: t.ip, value: t.count, color: 'var(--orange)'
    })));
  }

  /* 위협유형 코드 → 한글(전역 라벨맵 있으면 사용) */
  function threatLabel(t) {
    const m = (window._threatTypeLabels || {});
    return m[t] || t;
  }

  /* 일별 심각도 누적 막대 (SVG) */
  function renderDailyBars(elId, days) {
    const svg = document.getElementById(elId);
    if (!svg) return;
    const W = svg.clientWidth || 800, H = 200;
    const padL = 34, padR = 8, padT = 10, padB = 40;
    if (!days.length) {
      svg.innerHTML = `<text x="${W/2}" y="100" text-anchor="middle" font-size="12" fill="#8b949e">데이터 없음</text>`;
      return;
    }
    const max = Math.max(1, ...days.map(d => d.total));
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const bw = Math.max(6, Math.min(48, plotW / days.length * 0.7));
    const gap = plotW / days.length;
    const y = v => padT + plotH - (v / max * plotH);
    let out = '';
    // y축 격자 (0, 50%, 100%)
    [0, 0.5, 1].forEach(f => {
      const yy = padT + plotH - f * plotH;
      out += `<line x1="${padL}" y1="${yy}" x2="${W-padR}" y2="${yy}" stroke="#30363d" stroke-width="1"/>
              <text x="${padL-4}" y="${yy+3}" text-anchor="end" font-size="9" fill="#8b949e">${Math.round(max*f).toLocaleString()}</text>`;
    });
    days.forEach((d, i) => {
      const cx = padL + gap * i + (gap - bw) / 2;
      let yb = padT + plotH;
      [['other', '#8b949e'], ['high', 'var(--orange)'], ['critical', 'var(--red)']].forEach(([key, col]) => {
        const v = d[key] || 0;
        if (v <= 0) return;
        const h = v / max * plotH;
        yb -= h;
        out += `<rect x="${cx}" y="${yb}" width="${bw}" height="${h}" fill="${col}"><title>${d.date} ${key}: ${v}</title></rect>`;
      });
      // 날짜 라벨 (MM-DD, 회전)
      const lab = (d.date || '').slice(5);
      out += `<text x="${cx + bw/2}" y="${H - padB + 14}" text-anchor="end" font-size="9" fill="#8b949e"
                transform="rotate(-45 ${cx + bw/2} ${H - padB + 14})">${lab}</text>`;
    });
    svg.innerHTML = out;
  }

  /* 요일(0=일)×시간(0~23) 히트맵 */
  function renderHeatmap(elId, heat) {
    const svg = document.getElementById(elId);
    if (!svg) return;
    const W = svg.clientWidth || 700, H = 220;
    const padL = 30, padT = 14, padB = 20;
    const dows = ['일', '월', '화', '수', '목', '금', '토'];
    const cw = (W - padL - 6) / 24, ch = (H - padT - padB) / 7;
    let max = 1;
    heat.forEach(row => row.forEach(v => { if (v > max) max = v; }));
    let out = '';
    // 시간 라벨 (0,6,12,18,23)
    [0, 6, 12, 18, 23].forEach(h => {
      out += `<text x="${padL + h*cw + cw/2}" y="${padT-3}" text-anchor="middle" font-size="9" fill="#8b949e">${h}</text>`;
    });
    for (let dw = 0; dw < 7; dw++) {
      out += `<text x="${padL-4}" y="${padT + dw*ch + ch/2 + 3}" text-anchor="end" font-size="9" fill="#8b949e">${dows[dw]}</text>`;
      for (let h = 0; h < 24; h++) {
        const v = (heat[dw] && heat[dw][h]) || 0;
        const t = v / max;
        // cyan 계열 농도
        const alpha = v === 0 ? 0.04 : 0.15 + t * 0.85;
        out += `<rect x="${padL + h*cw + 0.5}" y="${padT + dw*ch + 0.5}" width="${cw-1}" height="${ch-1}" rx="1"
                  fill="rgba(57,208,216,${alpha.toFixed(3)})"><title>${dows[dw]}요일 ${h}시: ${v}건</title></rect>`;
      }
    }
    svg.innerHTML = out;
  }

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    loadMetrics, runArchive,
  });
})();
