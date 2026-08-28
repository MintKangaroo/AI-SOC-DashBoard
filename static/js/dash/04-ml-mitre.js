/* dashboard/04-ml-mitre.js — ML 자체 모델·MITRE ATT&CK
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
(function () {
  /* ════════════════════ ML 자체 모델 ════════════════════ */
  let ifScoreChart   = null;
  let mlPanelInited  = false;

  function initMLCharts() {
    if (mlPanelInited) return;
    mlPanelInited = true;

    ifScoreChart = new Chart(document.getElementById('if-score-chart').getContext('2d'), {
      type: 'line',
      data: { labels:[], datasets:[
        { label:'IF 점수', data:[], borderColor:'#39d0d8', backgroundColor:'#39d0d811',
          tension:0.3, fill:true, pointRadius:2, borderWidth:2 },
      ]},
      options: {
        animation:false,
        plugins:{ legend:{ display:false } },
        scales: {
          x:{ ticks:{color:'#8b949e',font:{size:9},maxTicksLimit:8}, grid:{color:'#21262d'} },
          y:{ ticks:{color:'#8b949e',font:{size:9}}, grid:{color:'#21262d'} },
        },
      },
    });

    loadMLStatus();
  }

  /* Socket 이벤트: ML 모델 준비 완료 */
  socket.on('ml_model_ready', data => {
    document.getElementById('ml-status-badge').textContent = '운영 중';
  });

  /* Socket 이벤트: ML 분석 결과 */
  socket.on('ml_analysis', data => {
    if (isPanelVisible('ml')) {
      updateMLDisplay(data);
      appendMLLog(data);
    }
    updateOverviewML(data);
  });

  function updateOverviewML(data) {
    // IF
    const ifAnom = data.isolation_forest?.anomaly;
    const ifB = document.getElementById('ov-if-badge');
    if (ifB) ifB.className = 'badge me-1 ' + (ifAnom ? 'bg-danger' : 'bg-success');
    const ifC = document.getElementById('ov-if-anom');
    if (ifC && ifAnom) ifC.textContent = parseInt(ifC.textContent || 0) + 1;

    // RF / LSTM / Q-Learning 은 experimental/ 로 격리됨 — 오버뷰 표기 없음

    // ML 이상탐지 KPI
    if (ifAnom) {
      const el = document.getElementById('kpi-ml-anomaly');
      if (el) el.textContent = parseInt(el.textContent || 0) + 1;
    }
  }

  function updateMLDisplay(data) {
    // 모델 로드 전에는 점수가 없다 — 0으로 그리면 '정상'으로 오독된다.
    if (data.model_ready === false) return;
    // IF
    const ifRes = data.isolation_forest || {};
    if (ifRes.score !== undefined) {
      const score = ifRes.score;
      if (ifScoreChart) {
        const ts = data.timestamp?.split(' ')[1] || '';
        ifScoreChart.data.labels.push(ts);
        ifScoreChart.data.datasets[0].data.push(score);
        if (ifScoreChart.data.labels.length > 30) {
          ifScoreChart.data.labels.shift();
          ifScoreChart.data.datasets[0].data.shift();
        }
        ifScoreChart.update('none');
      }
    }

    // 통계 업데이트
    if (data.isolation_forest?.anomaly) {
      const el = document.getElementById('ml-if-anomalies');
      if (el) el.textContent = parseInt(el.textContent || 0) + 1;
    }
  }

  function appendMLLog(data) {
    const log = document.getElementById('ml-log');
    if (!log) return;
    const sev = data.summary?.severity || 'NORMAL';
    const threats = (data.summary?.threats || []).join(', ') || '없음';
    const score = data.isolation_forest?.score;
    const div = document.createElement('div');
    div.className = 'd-flex gap-3 py-1 border-bottom border-secondary align-items-center';
    div.setAttribute('style', 'color:#e6edf3');
    div.innerHTML = `
      <span style="min-width:60px;color:#e6edf3">${escapeHtml(data.timestamp?.split(' ')[1] || '')}</span>
      <span>${sevBadge(sev)}</span>
      <span style="color:#e6edf3">IF 점수: <strong>${score !== undefined ? score : '-'}</strong></span>
      <span style="color:#e6edf3">탐지: ${escapeHtml(threats)}</span>`;
    log.insertBefore(div, log.firstChild);
    while (log.children.length > 30) log.removeChild(log.lastChild);
  }

  function loadMLStatus() {
    fetch('/api/ml/status').then(r => r.json()).then(d => {
      const s = d.stats || {};
      const el = document.getElementById('ml-status-badge');
      if (el) el.textContent = s.model_status || '-';
      const ifa = document.getElementById('ml-if-anomalies');
      if (ifa) ifa.textContent = s.if_anomalies || 0;
      const trained = document.getElementById('ml-trained-on');
      if (trained) trained.textContent = s.trained_on === 'real' ? '실트래픽' : '합성(미검증)';
      const fb = document.getElementById('ml-feedback-count');
      if (fb) {
        const f = s.feedback || {};
        fb.textContent = `정탐 ${f.true_positive || 0} · 오탐 ${f.false_positive || 0}`;
      }
    });
  }

  function triggerMLAnalysis() {
    fetch('/api/ml/analyze', { method: 'POST' })
      .then(r => r.json())
      .then(d => { updateMLDisplay(d); appendMLLog(d); });
  }

  function sendFeedback(isFP) {
    fetch('/api/ml/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_false_positive: isFP }),
    });
  }

  /* ════════════════════ MITRE ATT&CK ════════════════════ */
  let mitreMatrixData = null;

  function loadMitreMatrix() {
    fetch('/api/mitre/matrix')
      .then(r => r.json())
      .then(d => {
        mitreMatrixData = d;
        renderMitreMatrix(d);
        updateMitreStats(d);
      });
    loadMitreCoverage();
    loadMitreTop();
    loadMitreRecent();
    loadMitreLog();
  }

  /* ── 상세 MITRE 로그 테이블 ── */
  const mitreLogBuffer = [];
  const MITRE_LOG_MAX = 200;

  function loadMitreLog() {
    fetch('/api/mitre/recent?limit=' + MITRE_LOG_MAX)
      .then(r => r.json())
      .then(d => {
        mitreLogBuffer.length = 0;
        (d.events || []).forEach(e => mitreLogBuffer.push(e));
        renderMitreLog();
      });
  }

  function renderMitreLog() {
    const tbody = document.getElementById('mitre-log-tbody');
    if (!tbody) return;
    const sevFilter = (document.getElementById('mitre-log-sev-filter')?.value || '').trim();
    const kwFilter  = (document.getElementById('mitre-log-filter')?.value || '').trim().toLowerCase();

    const filtered = mitreLogBuffer.filter(e => {
      if (sevFilter && (e.severity || '').toUpperCase() !== sevFilter) return false;
      if (kwFilter) {
        const hay = `${e.src_ip||''} ${e.dst_ip||''} ${e.technique_id||''} ${e.technique_ko||''} ${e.description||''}`.toLowerCase();
        if (!hay.includes(kwFilter)) return false;
      }
      return true;
    });

    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center p-3">일치하는 이벤트 없음</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.slice(0, 200).map(e => mitreLogRow(e)).join('');
  }

  function mitreLogRow(e) {
    const sev = (e.severity || 'MEDIUM').toUpperCase();
    const sevCls = sev === 'CRITICAL' ? 'badge bg-danger'
                : sev === 'HIGH'     ? 'badge bg-orange'
                : sev === 'MEDIUM'   ? 'badge bg-warning text-dark'
                : 'badge bg-secondary';
    const time = (e.timestamp || '').split(' ')[1] || e.timestamp || '';
    return `<tr style="color:#e6edf3">
      <td style="font-size:11px;color:#e6edf3">${time}</td>
      <td><span class="${sevCls}" style="font-size:10px">${sev}</span></td>
      <td><span class="small" style="color:#e6edf3">${escapeHtml(e.tactic_ko || e.tactic_id || '')}</span></td>
      <td>
        <a href="javascript:;" onclick="showTechniqueDetail('${escapeHtml(e.technique_id)}')" class="text-info font-monospace me-1">${escapeHtml(e.technique_id)}</a>
        <span class="small" style="color:#e6edf3">${escapeHtml(e.technique_ko || '')}</span>
      </td>
      <td class="font-monospace small" style="color:#e6edf3">${e.src_ip || '-'}</td>
      <td class="font-monospace small" style="color:#e6edf3">${e.dst_ip || '-'}</td>
      <td class="small" style="color:#e6edf3">${e.process || '-'}</td>
      <td class="small" style="color:#e6edf3">${escapeHtml(e.description || '')}</td>
    </tr>`;
  }

  document.addEventListener('DOMContentLoaded', () => {
    const sf = document.getElementById('mitre-log-sev-filter');
    const kf = document.getElementById('mitre-log-filter');
    if (sf) sf.addEventListener('change', renderMitreLog);
    if (kf) kf.addEventListener('input', renderMitreLog);
  });

  /* ── 탐지 커버리지 자가 진단 (docs/AUDIT.md 3단계 제안 A) ── */
  let _mitreView = 'hits';          // 'hits' | 'coverage'
  let _covByTechnique = {};         // technique id -> 진단 결과
  let _lastMatrix = null;           // 뷰 전환 시 재요청 없이 다시 그리기 위해 보관

  function setMitreView(view) {
    _mitreView = view === 'coverage' ? 'coverage' : 'hits';
    const hitsBtn = document.getElementById('mitre-view-hits');
    const covBtn = document.getElementById('mitre-view-coverage');
    const on = 'btn-cyan', off = 'btn-outline-cyan';
    if (hitsBtn) hitsBtn.className = `btn btn-xs ${_mitreView === 'hits' ? on : off}`;
    if (covBtn) covBtn.className = `btn btn-xs ${_mitreView === 'coverage' ? on : off}`;
    const hint = document.getElementById('mitre-view-hint');
    if (hint) {
      hint.textContent = _mitreView === 'coverage'
        ? '초록=룰+검증 · 노랑=룰만 · 빨강 점선=공백(룰 없음)'
        : '탐지된 Technique는 빨간색 강조 · 셀 클릭 시 상세';
    }
    if (_lastMatrix) renderMitreMatrix(_lastMatrix);
  }

  function loadMitreCoverage() {
    return fetch('/api/mitre/coverage')
      .then(r => r.json())
      .then(d => { renderMitreCoverage(d); return d; })
      .catch(() => {});
  }

  function renderMitreCoverage(d) {
    const s = d.summary || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('cov-rule-pct', `${s.rule_pct ?? 0}%`);
    set('cov-validated-pct', `${s.validated_pct ?? 0}%`);
    set('cov-gaps', s.gaps ?? 0);
    set('cov-seen', s.seen ?? 0);

    _covByTechnique = {};
    (d.tactics || []).forEach(tac => (tac.techniques || []).forEach(t => {
      _covByTechnique[t.id] = t;
    }));

    /* 룰·시나리오는 있는데 매트릭스에 칸이 없는 기법 — 탐지돼도 표시될 곳이 없다.
       이 목록이 비어 있어야 정상이다. */
    const un = document.getElementById('cov-untracked');
    if (un) {
      const rows = d.untracked || [];
      un.innerHTML = rows.length
        ? `<div class="text-warning"><i class="fa fa-triangle-exclamation me-1"></i>`
          + `매트릭스에 칸이 없는 기법 ${rows.length}개 — 탐지돼도 표시되지 않는다: `
          + rows.map(r => escapeHtml(r.technique_id)).join(', ') + '</div>'
        : '';
    }

    const list = document.getElementById('cov-gap-list');
    const badge = document.getElementById('cov-gap-badge');
    const gaps = d.gaps || [];
    if (badge) badge.textContent = `${gaps.length}개`;
    if (list) {
      list.innerHTML = gaps.length
        ? gaps.map(g => `<div class="cov-gap-row">
            <span class="tac">${escapeHtml(g.tactic_ko)}</span>
            <span class="tid">${escapeHtml(g.technique_id)}</span>
            <span class="tko">${escapeHtml(g.ko)}</span>
            ${g.hits ? `<span class="ms-auto badge bg-warning text-dark">히트 ${g.hits}건인데 룰 없음</span>` : ''}
          </div>`).join('')
        : '<div class="text-success p-2">공백 없음 — 매트릭스의 모든 기법에 룰이 있다.</div>';
    }
    if (_mitreView === 'coverage' && _lastMatrix) renderMitreMatrix(_lastMatrix);
  }

  function renderMitreMatrix(data) {
    _lastMatrix = data;
    const container = document.getElementById('mitre-matrix-container');
    if (!container) return;

    const tactics = data.tactics || [];
    let html = '<div class="mitre-matrix">';

    tactics.forEach(tac => {
      html += `<div class="mitre-tactic">
        <div class="mitre-tactic-header" title="${escapeHtml(tac.name)} (${escapeHtml(tac.id)})">
          <span class="t-ko">${escapeHtml(tac.ko)}</span>
          <span class="t-en">${escapeHtml(tac.name)}</span>
          <span class="t-count">${tac.total}</span>
        </div>`;

      (tac.techniques || []).forEach(tech => {
        const count = tech.count || 0;
        let hitClass = '';
        if (count > 0 && count < 3)        hitClass = 'hit-low';
        else if (count < 10)                hitClass = 'hit-med';
        else if (count >= 10)               hitClass = 'hit-high';

        /* 커버리지 뷰에서는 히트 색 대신 '룰이 있는가/검증됐는가'로 칠한다.
           히트 0 인 칸이 공격이 없었던 건지 못 보는 건지 여기서 갈린다. */
        let title = `${tech.name} — 탐지 ${count}건 · 클릭 시 상세`;
        if (_mitreView === 'coverage') {
          const cov = _covByTechnique[tech.id];
          hitClass = cov ? 'cov-' + cov.state : 'cov-gap';
          title = cov
            ? `${tech.name} — ${cov.state_label}`
              + (cov.rules.length ? ` · 룰 ${cov.rules.map(r => r.source).join('/')}` : '')
              + (cov.validated ? ' · 퍼플팀 검증' : '')
              + ` · 탐지 ${count}건`
            : `${tech.name} — 진단 정보 없음`;
        }

        html += `<div class="mitre-technique clickable ${hitClass}"
                      title="${escapeHtml(title)}"
                      onclick="showTechniqueDetail('${escapeHtml(tech.id)}')"
                      data-tactic="${escapeHtml(tac.id)}" data-technique="${escapeHtml(tech.id)}">
          <div class="tech-id">${escapeHtml(tech.id)}</div>
          <div class="tech-name">${escapeHtml(tech.ko)}</div>
          ${count > 0 ? `<div class="tech-count">${count}</div>` : ''}
        </div>`;
      });

      html += '</div>';
    });

    html += '</div>';
    container.innerHTML = html;
  }

  /* ── Technique 상세 모달 ── */
  function showTechniqueDetail(techId) {
    const modalEl = document.getElementById('mitreDetailModal');
    if (!modalEl) return;
    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    const body  = document.getElementById('mitre-detail-body');
    const title = document.getElementById('mitre-detail-title');
    const ref   = document.getElementById('mitre-detail-ref');
    title.innerHTML = `<i class="fa fa-crosshairs text-danger me-2"></i>${techId} 로딩 중...`;
    body.innerHTML = '<div class="text-center text-muted py-5"><i class="fa fa-spinner fa-spin fa-2x"></i></div>';
    ref.href = `https://attack.mitre.org/techniques/${techId}/`;
    modal.show();

    fetch(`/api/mitre/technique/${techId}`)
      .then(r => r.json())
      .then(d => {
        if (!d.found) {
          body.innerHTML = `<div class="alert alert-warning">${d.message || '해당 Technique 정보가 없습니다.'}</div>`;
          return;
        }
        title.innerHTML = `<i class="fa fa-crosshairs text-danger me-2"></i>${escapeHtml(d.technique_id)} · ${escapeHtml(d.technique_ko)}
          <span class="badge bg-secondary ms-2" style="font-size:11px">${escapeHtml(d.tactic_id)} · ${escapeHtml(d.tactic_ko)}</span>`;
        ref.href = d.reference_url;

        const sev = d.severity_dist || {};
        const sevHtml = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => {
          const c = sev[s] || 0;
          const cls = s === 'CRITICAL' ? 'bg-danger'
                   : s === 'HIGH'     ? 'bg-orange'
                   : s === 'MEDIUM'   ? 'bg-warning text-dark'
                   : 'bg-secondary';
          return c ? `<span class="badge ${cls} me-1">${s} ${c}</span>` : '';
        }).join('');

        const rowHtml = arr => arr.length
          ? arr.map(x => `<tr><td class="font-monospace">${x.ip||x.name}</td><td class="text-end">${x.count}</td></tr>`).join('')
          : '<tr><td colspan="2" class="text-muted text-center">-</td></tr>';

        const recentHtml = (d.recent||[]).length
          ? d.recent.map(e => {
              const sevCls = e.severity === 'CRITICAL' ? 'text-danger'
                          : e.severity === 'HIGH'     ? 'text-orange'
                          : 'text-warning';
              return `<tr>
                <td class="text-muted" style="font-size:11px">${e.timestamp.split(' ')[1] || e.timestamp}</td>
                <td class="${sevCls}">${e.severity||'-'}</td>
                <td class="font-monospace">${e.src_ip||'-'}</td>
                <td class="font-monospace">${e.dst_ip||'-'}</td>
                <td>${escapeHtml(e.description||'')}</td>
              </tr>`;
            }).join('')
          : '<tr><td colspan="5" class="text-muted text-center">기록 없음</td></tr>';

        const defenseHtml = (d.defense||[]).length
          ? '<ul class="mb-0 ps-3">' + d.defense.map(x => `<li>${escapeHtml(x)}</li>`).join('') + '</ul>'
          : '<div class="text-muted">권고사항 없음</div>';

        body.innerHTML = `
          <div class="mb-3" style="color:#e6edf3">${escapeHtml(d.description||'')}</div>
          <div class="row g-3 mb-3">
            <div class="col-sm-4"><div class="stat-card stat-sm border-danger">
              <div class="stat-value">${(d.total_count||0).toLocaleString()}</div>
              <div class="stat-label">총 탐지 건수</div>
            </div></div>
            <div class="col-sm-8"><div class="p-2" style="background:rgba(255,255,255,.03);border-radius:6px">
              <div class="small mb-1" style="color:#e6edf3">심각도 분포</div>
              <div>${sevHtml || '<span style="color:#e6edf3">-</span>'}</div>
            </div></div>
          </div>

          <div class="row g-3 mb-3">
            <div class="col-md-4">
              <h6 class="text-cyan"><i class="fa fa-location-dot me-1"></i>TOP 출발 IP</h6>
              <table class="table table-dark table-sm table-striped mb-0"><tbody>${rowHtml(d.top_src_ips||[])}</tbody></table>
            </div>
            <div class="col-md-4">
              <h6 class="text-orange"><i class="fa fa-crosshairs me-1"></i>TOP 목적 IP</h6>
              <table class="table table-dark table-sm table-striped mb-0"><tbody>${rowHtml(d.top_dst_ips||[])}</tbody></table>
            </div>
            <div class="col-md-4">
              <h6 class="text-purple"><i class="fa fa-microchip me-1"></i>TOP 프로세스</h6>
              <table class="table table-dark table-sm table-striped mb-0"><tbody>${rowHtml(d.top_processes||[])}</tbody></table>
            </div>
          </div>

          <h6 class="text-info"><i class="fa fa-clock-rotate-left me-1"></i>최근 이벤트 (상위 30건)</h6>
          <div style="max-height:260px;overflow-y:auto" class="mb-3">
            <table class="table table-dark table-sm table-hover mb-0">
              <thead><tr><th>시각</th><th>심각도</th><th>출발 IP</th><th>목적 IP</th><th>설명</th></tr></thead>
              <tbody>${recentHtml}</tbody>
            </table>
          </div>

          <h6 class="text-success"><i class="fa fa-shield me-1"></i>방어 권고</h6>
          ${defenseHtml}
        `;
      })
      .catch(e => {
        body.innerHTML = `<div class="alert alert-danger">로딩 오류: ${e}</div>`;
      });
  }

  /* escapeHtml 은 01-core.js 로 이동했다 — 1번 파일부터 쓰이는 공용 헬퍼가
     4번 파일에 정의돼 있어 로드 순서에 취약했다. */

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    MITRE_LOG_MAX, initMLCharts, loadMitreCoverage, loadMitreMatrix, mitreLogBuffer,
    renderMitreLog, sendFeedback, setMitreView, showTechniqueDetail, triggerMLAnalysis,
  });
})();
