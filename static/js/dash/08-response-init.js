/* dashboard/08-response-init.js — SOAR·ML 의사결정·인시던트·초기화
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
(function () {
  /* ════════════════════ SOAR 자동 대응 ════════════════════ */
  /* ── 차단 결정 재현 (docs/AUDIT.md 3단계 제안 C) ── */

  function loadBlockDecisions() {
    const sel = document.getElementById('bd-filter');
    // HTML 이 아니라 URL 로 들어가는 값이다 — escapeHtml 이 아니라 인코딩이 맞다
    const q = sel && sel.value !== 'all'
      ? '?' + new URLSearchParams({ blocked: sel.value }).toString() : '';
    fetch('/api/soar/decisions' + q)
      .then(r => r.json())
      .then(renderBlockDecisions)
      .catch(() => {});
  }

  function renderBlockDecisions(d) {
    const summary = document.getElementById('bd-summary');
    const tbody = document.getElementById('bd-tbody');
    if (summary) {
      if (!d.enabled) {
        summary.textContent = '결정 로그가 비활성입니다.';
      } else {
        const s = d.stats || {};
        const top = (s.top_blockers || [])[0];
        summary.innerHTML =
          `총 <b>${s.total || 0}</b>건 · 차단 <b class="text-danger">${s.blocked || 0}</b> · `
          + `차단 안 함 <b>${s.skipped || 0}</b>`
          + (top ? ` · 가장 자주 막은 조건: <b class="text-warning">${escapeHtml(top.label)}</b> (${top.count}건)` : '');
      }
    }
    if (!tbody) return;
    const rows = d.decisions || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-muted text-center p-3">결정 기록 없음</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => {
      const badge = r.blocked
        ? '<span class="badge bg-danger">차단됨</span>'
        : `<span class="badge bg-secondary">${escapeHtml(r.outcome_label || '차단 안 함')}</span>`;
      const blockers = (r.blocked_by || []).length
        ? (r.gates || []).filter(g => !g.passed)
            .map(g => `<span class="bd-gate fail">${escapeHtml(g.label)}</span>`).join('')
        : '<span class="text-muted">—</span>';
      const conf = r.signals && r.signals.confidence != null ? r.signals.confidence + '%' : '-';
      return `<tr>
        <td class="font-monospace">${escapeHtml(r.ts)}</td>
        <td class="font-monospace">${escapeHtml(r.src_ip || '-')}</td>
        <td>${badge}</td>
        <td>${blockers}</td>
        <td class="font-monospace">${escapeHtml(conf)}</td>
        <td><button class="btn btn-xs btn-outline-cyan"
                    onclick="showBlockDecision(${Number(r.id)})">근거</button></td>
      </tr>`;
    }).join('');
  }

  /* 결정 하나를 펼쳐 게이트별 통과 여부와 신호를 보여주고, 임계값을 바꿨다면
     결과가 달라졌을지 재생한다. 재생은 조회 전용이다 — 실제 차단을 하지 않는다. */
  function showBlockDecision(id) {
    fetch(`/api/soar/decisions/${id}`)
      .then(r => r.json())
      .then(rec => {
        const box = document.getElementById('bd-detail');
        if (!box || rec.error) return;
        const gates = (rec.gates || []).map(g =>
          `<span class="bd-gate ${g.passed ? 'pass' : 'fail'}">`
          + `${g.passed ? '✓' : '✗'} ${escapeHtml(g.label)}`
          + (g.id === 'confidence' ? ` (${escapeHtml(g.actual)}/${escapeHtml(g.required)})` : '')
          + '</span>').join('');
        const sig = rec.signals || {};
        box.innerHTML = `
          <div class="bd-replay">
            <div class="mb-1"><b>결정 #${Number(rec.id)}</b>
              <span class="font-monospace ms-2">${escapeHtml(rec.src_ip || '-')}</span>
              <span class="badge ${rec.blocked ? 'bg-danger' : 'bg-secondary'} ms-2">${escapeHtml(rec.outcome_label || '')}</span>
            </div>
            <div class="mb-1">${gates}</div>
            <div class="small text-muted mb-1">
              판정: ${escapeHtml(sig.verdict_by || '-')} ·
              평판: ${escapeHtml((sig.ip_reputation || {}).score ?? '-')} ·
              근거: ${escapeHtml((sig.evidence || []).join(', ') || '없음')}
              ${sig.ai_summary ? `<br/>AI: ${escapeHtml(sig.ai_summary)}` : ''}
            </div>
            <div class="d-flex align-items-center gap-2 mt-2">
              <span class="small">임계값을 바꿨다면?</span>
              <input id="bd-replay-conf" type="number" min="0" max="100" value="${Number(rec.thresholds?.min_block_confidence ?? 95)}"
                     class="form-control form-control-sm bg-dark text-white border-secondary" style="width:90px">
              <label class="form-check form-switch small mb-0">
                <input id="bd-replay-corr" class="form-check-input" type="checkbox"
                       ${rec.thresholds?.require_corroboration ? 'checked' : ''}> 독립 근거 요구
              </label>
              <button class="btn btn-xs btn-cyan" onclick="replayBlockDecision(${Number(rec.id)})">재생</button>
            </div>
            <div id="bd-replay-out" class="small mt-2"></div>
          </div>`;
      })
      .catch(() => {});
  }

  function replayBlockDecision(id) {
    const conf = document.getElementById('bd-replay-conf');
    const corr = document.getElementById('bd-replay-corr');
    const p = new URLSearchParams({
      min_confidence: conf ? conf.value : '',
      require_corroboration: corr && corr.checked ? 'true' : 'false',
    });
    fetch(`/api/soar/decisions/${id}/replay?` + p.toString())
      .then(r => r.json())
      .then(res => {
        const out = document.getElementById('bd-replay-out');
        if (!out || res.error) return;
        const before = res.original.blocked ? '차단' : '차단 안 함';
        const after = res.replayed.blocked ? '차단' : '차단 안 함';
        const left = (res.replayed.blocked_by || []).length
          ? ` · 남은 미충족: ${res.replayed.blocked_by.map(escapeHtml).join(', ')}` : '';
        out.innerHTML = res.changed
          ? `<span class="flip">결과가 바뀐다: ${escapeHtml(before)} → ${escapeHtml(after)}</span>${left}`
          : `결과 동일 (${escapeHtml(after)})${left}`;
      })
      .catch(() => {});
  }

  function loadSoar() {
    loadBlockDecisions();
    fetch('/api/soar/status')
      .then(r => r.json())
      .then(renderSoar)
      .catch(() => {});
  }

  let _soarStatus = null;   // 판정 상세 모달이 참조할 최신 SOAR 상태 캐시

  // 플레이북 단계 유형 → 색상/한글
  const PB_STEP_KIND = {
    detect:   { ko: '탐지', color: '#58a6ff' },
    enrich:   { ko: '강화', color: '#a371f7' },
    decide:   { ko: '판정', color: '#f0a500' },
    contain:  { ko: '대응', color: '#f85149' },
    notify:   { ko: '통보', color: '#39d0d8' },
    followup: { ko: '사후', color: '#3fb950' },
  };

  function renderPlaybookCard(pb) {
    const steps = (pb.steps || []).map((s, i) => {
      const k = PB_STEP_KIND[s.kind] || { ko: '', color: '#8b949e' };
      const arrow = i > 0 ? '<span class="pb-arrow">→</span>' : '';
      return `${arrow}<span class="pb-step" style="border-color:${k.color}">
        <span class="pb-step-kind" style="background:${k.color}">${k.ko}</span>
        <span class="pb-step-label">${escapeHtml(s.label)}</span>
      </span>`;
    }).join('');
    const dim = pb.enabled ? '' : 'opacity:.45;';
    return `
      <div class="pb-card" style="${dim}">
        <div class="d-flex align-items-center gap-2 mb-1">
          <div class="form-check form-switch mb-0">
            <input class="form-check-input" type="checkbox" ${pb.enabled ? 'checked' : ''}
                   onchange="soarTogglePb('${escapeHtml(pb.id)}')">
          </div>
          <span class="badge bg-dark border border-secondary font-monospace" style="font-size:9px">${escapeHtml(pb.id)}</span>
          <span class="small fw-bold flex-fill" style="color:#e6edf3">${escapeHtml(pb.name)}</span>
          <span class="small text-muted" style="font-size:10px; white-space:nowrap">
            실행 <b class="text-cyan">${pb.runs}</b>회${pb.last_run ? ` · ${escapeHtml(pb.last_run.slice(11))}` : ''}
          </span>
        </div>
        <div class="small text-muted mb-2" style="font-size:10px">${escapeHtml(pb.description)}</div>
        <div class="pb-flow">${steps || '<span class="text-muted small">단계 정의 없음</span>'}</div>
      </div>`;
  }

  function renderSoar(d) {
    _soarStatus = d;
    const stats = d.stats || {};
    const set = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = (v ?? 0).toLocaleString();
    };
    set('soar-total-actions', stats.total_actions);
    set('soar-blocked', stats.auto_blocked);
    set('soar-closed-fp', stats.auto_closed_fp);
    set('soar-escalated', stats.escalated_tp);
    set('sidebar-soar-count', stats.total_actions);
    const modeEl = document.getElementById('soar-mode-label');
    if (modeEl) modeEl.textContent = d.block_mode || 'simulate';
    // 안전장치 정보
    const safety = d.safety || {};
    const prevEl = document.getElementById('soar-prevented');
    if (prevEl) prevEl.textContent = (safety.prevented || 0).toLocaleString();
    const extraEl = document.getElementById('soar-safety-extra');
    if (extraEl) {
      const allow = safety.allowlist || [];
      extraEl.innerHTML = allow.length
        ? `추가 화이트리스트: <span class="font-monospace text-warning">${allow.map(escapeHtml).join(', ')}</span>. `
        : '';
    }
    // 파이프라인: AI 트리아지 + SOAR 대응
    setPipe('pipe-ai-triage', stats.ai_triages);
    setPipe('pipe-ai-tp', stats.escalated_tp);
    setPipe('pipe-ai-fp', stats.auto_closed_fp);
    setPipe('pipe-soar-actions', stats.total_actions);
    setPipe('pipe-soar-blocked', stats.auto_blocked);

    // 플레이북 — 단계 흐름도(runbook) 시각화
    const pbBox = document.getElementById('soar-playbooks');
    if (pbBox) {
      pbBox.innerHTML = (d.playbooks || []).map(renderPlaybookCard).join('');
    }

    const vt = d.virustotal || {};
    const vtEl = document.getElementById('soar-vt-status');
    if (vtEl) vtEl.innerHTML = vt.active
      ? '<span class="badge bg-success">VirusTotal 연결됨 · 해시 조회 전용</span>'
      : '<span class="badge bg-secondary">VirusTotal API 키 미설정</span>';
    renderSoarExecutions(d.executions || []);
    renderOverviewFlowControl(d);

    // 차단 IP 목록
    const blBox = document.getElementById('soar-blocklist');
    if (blBox) {
      const ips = d.blocked_ips || [];
      blBox.innerHTML = ips.length
        ? ips.map(b => `
            <div class="d-flex align-items-center p-1 border-bottom border-secondary small">
              <span class="font-monospace text-danger me-2">${escapeHtml(b.ip)}</span>
              <span class="badge ${b.mode === 'simulate' ? 'bg-secondary' : 'bg-danger'}"
                    style="font-size:9px">${escapeHtml(b.mode)}</span>
              <span class="text-muted ms-2 text-truncate" style="font-size:10px; max-width:150px"
                    title="${escapeHtml(b.reason)}">${escapeHtml(b.reason)}</span>
              <span class="text-warning ms-1" style="font-size:9px; white-space:nowrap"
                    title="자동 만료 시각">${escapeHtml((b.expires || '').replace(/^\d{4}-/, ''))}</span>
              <button class="btn btn-xs btn-outline-secondary ms-auto" style="font-size:9px"
                      onclick="soarUnblock('${escapeHtml(b.ip)}')">해제</button>
            </div>`).join('')
        : '<div class="text-muted p-2">차단된 IP 없음</div>';
    }

    // 대응 타임라인
    const tbody = document.getElementById('soar-actions-tbody');
    if (tbody) {
      const rows = (d.actions || []).map(soarActionRow).join('');
      tbody.innerHTML = rows || '<tr><td colspan="6" class="text-muted text-center p-3">아직 대응 이력 없음</td></tr>';
    }
  }

  const SOAR_RUN_STATE = {pending:'대기', running:'진행 중', completed:'완료',
                          skipped:'건너뜀', failed:'실패', waiting_approval:'승인 대기',
                          processing_approval:'승인 처리 중', rejected:'거절',
                          cancelled:'취소', expired:'만료'};
  function renderSoarExecutions(runs) {
    const box = document.getElementById('soar-executions');
    if (!box) return;
    box.innerHTML = runs.length ? runs.slice(0, 12).map(run => `
      <div class="soar-run">
        <div class="d-flex align-items-center gap-2 small">
          <span class="pb-tag">${escapeHtml(run.playbook)}</span>
          <strong style="color:#e6edf3">${escapeHtml(run.target)}</strong>
          <span class="ms-auto badge ${run.status === 'running' ? 'bg-info text-dark' : run.status === 'waiting_approval' ? 'bg-warning text-dark' : ['failed','rejected','expired'].includes(run.status) ? 'bg-danger' : run.status === 'cancelled' ? 'bg-secondary' : 'bg-success'}">${escapeHtml(SOAR_RUN_STATE[run.status] || run.status)}</span>
          ${run.attempt > 1 ? `<span class="badge bg-secondary">${run.attempt}차 시도</span>` : ''}
          ${run.status === 'failed' && run.playbook === 'PB-MALWARE-ENRICH' ? `<button class="btn btn-xs btn-outline-warning" onclick="retrySoarExecution(${Number(run.id)})"><i class="fa fa-rotate-right me-1"></i>실패 단계 재시도</button>` : ''}
          ${run.status === 'waiting_approval' ? `<button class="btn btn-xs btn-success" onclick="reviewSoarApproval(${Number(run.id)},'approve')">승인</button><button class="btn btn-xs btn-outline-danger" onclick="reviewSoarApproval(${Number(run.id)},'reject')">거절</button><button class="btn btn-xs btn-outline-secondary" onclick="reviewSoarApproval(${Number(run.id)},'cancel')">취소</button>` : ''}
          <span class="text-muted font-monospace" style="font-size:9px">${escapeHtml((run.started || '').split(' ')[1] || '')}</span>
        </div>
        <div class="soar-run-steps">${(run.steps || []).map(step => `
          <div class="soar-run-step ${escapeHtml(step.status)}" title="${escapeHtml(step.detail || '')}">
            <span class="step-state">${escapeHtml(SOAR_RUN_STATE[step.status] || step.status)}</span>
            <span>${escapeHtml(step.label)}</span>
            ${step.detail ? `<div class="text-truncate mt-1">${escapeHtml(step.detail)}</div>` : ''}
          </div>`).join('')}</div>
      </div>`).join('') : '<div class="text-muted p-3 text-center small">실행 이력 없음</div>';
  }

  function reviewSoarApproval(id, decision) {
    const labels = {approve:'승인', reject:'거절', cancel:'취소'};
    const reason = prompt(`${labels[decision]} 사유를 입력하세요 (선택)`, '') ?? null;
    if (reason === null) return;
    fetch(`/api/soar/executions/${encodeURIComponent(id)}/approval`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({decision, reason})
    }).then(async r => ({ok:r.ok, data:await r.json()})).then(({ok,data}) => {
      if (!ok) throw new Error(data.status || '처리 실패');
      loadSoar();
    }).catch(e => alert(`승인 처리 실패: ${e.message}`));
  }

  let _overviewPendingApprovalIds = [];
  function approveAllSoar() {
    const ids = [..._overviewPendingApprovalIds];
    if (!ids.length) return;
    if (!confirm(`현재 화면의 승인 대기 ${ids.length}건을 모두 승인할까요?`)) return;
    const reason = prompt('일괄 승인 사유를 입력하세요 (선택)', '일괄 승인') ?? null;
    if (reason === null) return;
    fetch('/api/soar/approvals/batch', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({execution_ids:ids, reason})
    }).then(async r => ({ok:r.ok, data:await r.json()})).then(({ok,data}) => {
      if (!ok && !data.results) throw new Error(data.error || '일괄 승인 실패');
      alert(`일괄 승인 결과: 성공 ${data.approved || 0}건 · 실패 ${data.failed || 0}건`);
      loadSoar();
    }).catch(e => alert(`일괄 승인 실패: ${e.message}`));
  }

  function renderOverviewFlowControl(d) {
    const runs = d.executions || [];
    const pending = runs.filter(r => r.status === 'waiting_approval');
    _overviewPendingApprovalIds = pending.map(r => Number(r.id));
    const running = runs.filter(r => r.status === 'running').length;
    const failed = runs.filter(r => r.status === 'failed').length;
    const state = document.getElementById('overview-flow-state');
    if (state) state.innerHTML = `자동화 <b class="${d.auto_block ? 'text-success' : 'text-danger'}">${d.auto_block ? '활성' : '중지'}</b> · 승인 게이트 <b class="${d.approval_required ? 'text-warning' : 'text-muted'}">${d.approval_required ? `활성(${d.approval_timeout_minutes}분)` : '비활성'}</b> · 실행 중 <b class="text-info">${running}</b> · 실패 <b class="text-danger">${failed}</b>`;
    const count = document.getElementById('overview-approval-count');
    if (count) { count.textContent = pending.length; count.className = `badge ms-2 ${pending.length ? 'bg-warning text-dark' : 'bg-secondary'}`; }
    document.getElementById('overview-approve-all')?.classList.toggle('d-none', !pending.length);
    const box = document.getElementById('overview-approvals');
    if (box) box.innerHTML = pending.length ? pending.map(run => `
      <div class="priority-item">
        <div class="flex-fill clickable" onclick="showPanel('soar')">
          <div class="priority-title"><span class="font-monospace">${escapeHtml(run.target)}</span> 차단 승인</div>
          <div class="priority-meta">${escapeHtml(run.approval?.requested_by || '')} · ${escapeHtml(run.approval?.expires_at || '')} 만료</div>
        </div>
        <div class="d-flex gap-1 align-items-center"><button class="btn btn-xs btn-success" onclick="reviewSoarApproval(${Number(run.id)},'approve')">승인</button><button class="btn btn-xs btn-outline-danger" onclick="reviewSoarApproval(${Number(run.id)},'reject')">거절</button></div>
      </div>`).join('') : '<div class="small text-muted py-2">대기 중인 조치 없음</div>';
  }

  function retrySoarExecution(id) {
    fetch(`/api/soar/executions/${encodeURIComponent(id)}/retry`, {method:'POST'})
      .then(async r => ({ok:r.ok, data:await r.json()}))
      .then(({ok, data}) => {
        if (!ok) throw new Error(data.status || data.error || '재시도 실패');
        loadSoar();
      })
      .catch(e => alert(`SOAR 재시도 실패: ${e.message}`));
  }

  let _soarExecutionRenderTimer = null;
  socket.on('soar_execution', run => {
    const runs = ((_soarStatus && _soarStatus.executions) || []).filter(r => r.id !== run.id);
    runs.unshift(run);
    if (_soarStatus) _soarStatus.executions = runs.slice(0, 30);
    if (document.hidden || (!isPanelVisible('soar') && !isPanelVisible('overview'))) return;
    if (_soarExecutionRenderTimer) return;
    _soarExecutionRenderTimer = setTimeout(() => {
      _soarExecutionRenderTimer = null;
      const latest = (_soarStatus && _soarStatus.executions) || [];
      if (isPanelVisible('soar')) renderSoarExecutions(latest);
      if (isPanelVisible('overview') && _soarStatus) renderOverviewFlowControl(_soarStatus);
    }, 200);
  });

  // 정탐(tp)/오탐(fp) 카드·숫자 클릭 → SOAR 트리아지 상세 내역 모달
  function showVerdictDetail(kind) {
    const isFp = kind === 'fp';
    const wantAction = isFp ? 'auto_close' : 'escalate';
    const title = isFp ? '오탐 자동 종결 내역' : '정탐 에스컬레이션 내역';
    const icon = isFp
      ? '<i class="fa fa-circle-check text-success me-2"></i>'
      : '<i class="fa fa-arrow-up-right-dots text-warning me-2"></i>';
    const titleEl = document.getElementById('verdict-detail-title');
    const bodyEl = document.getElementById('verdict-detail-body');
    const modalEl = document.getElementById('verdictDetailModal');
    if (!modalEl || !bodyEl) return;
    if (titleEl) titleEl.innerHTML = icon + escapeHtml(title);

    const render = (d) => {
      const stats = (d && d.stats) || {};
      const total = isFp ? (stats.auto_closed_fp || 0) : (stats.escalated_tp || 0);
      const rows = ((d && d.actions) || []).filter(a => a.action === wantAction);
      let html = `<div class="small text-muted mb-2">누적 ${total.toLocaleString()}건 · 최근 이력 ${rows.length}건 표시</div>`;
      if (!rows.length) {
        html += `<div class="text-center text-muted py-4">표시할 최근 ${isFp ? '오탐' : '정탐'} 내역이 없습니다.</div>`;
      } else {
        html += '<div class="list-group list-group-flush">' + rows.map(a => `
          <div class="list-group-item bg-transparent border-secondary px-0 py-2">
            <div class="d-flex align-items-center gap-2">
              <span class="badge ${isFp ? 'bg-success' : 'bg-warning text-dark'}">${isFp ? '오탐' : '정탐'}</span>
              <span class="fw-bold" style="color:#e6edf3">${escapeHtml(a.target || '')}</span>
              <span class="text-muted ms-auto small font-monospace">${escapeHtml(a.timestamp || '')}</span>
            </div>
            <div class="small mt-1" style="color:#c9d3de">${escapeHtml(a.detail || '')}</div>
          </div>`).join('') + '</div>';
      }
      bodyEl.innerHTML = html;
    };

    bodyEl.innerHTML = '<div class="text-center text-muted py-5">로딩 중...</div>';
    bootstrap.Modal.getOrCreateInstance(modalEl).show();

    if (_soarStatus) {
      render(_soarStatus);
    } else {
      fetch('/api/soar/status').then(r => r.json()).then(d => { _soarStatus = d; render(d); })
        .catch(() => { bodyEl.innerHTML = '<div class="text-center text-danger py-4">불러오기 실패</div>'; });
    }
  }

  const SOAR_ACTION_LABELS = {
    block_ip: '<span class="badge bg-danger">IP 차단</span>',
    unblock: '<span class="badge bg-secondary">차단 해제</span>',
    auto_close: '<span class="badge bg-success">오탐 종결</span>',
    escalate: '<span class="badge bg-warning text-dark">에스컬레이션</span>',
    triage: '<span class="badge bg-info text-dark">트리아지</span>',
    incident: '<span class="badge bg-danger">인시던트</span>',
    vt_lookup: '<span class="badge bg-purple">VirusTotal</span>',
  };

  function soarActionRow(a) {
    return `
      <tr>
        <td class="small" style="color:#e6edf3; white-space:nowrap">${escapeHtml((a.timestamp || '').split(' ')[1] || a.timestamp)}</td>
        <td class="small" style="white-space:nowrap"><span class="pb-tag">${escapeHtml(a.playbook)}</span></td>
        <td class="small">${SOAR_ACTION_LABELS[a.action] || escapeHtml(a.action)}</td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(a.target)}</td>
        <td class="small ${a.result === 'success' ? 'text-success' : 'text-muted'}">${escapeHtml(a.result)}</td>
        <td class="small text-truncate" style="max-width:260px; color:#e6edf3" title="${escapeHtml(a.detail)}">${escapeHtml(a.detail)}</td>
      </tr>`;
  }

  function soarTogglePb(pbId) {
    fetch(`/api/soar/playbooks/${encodeURIComponent(pbId)}/toggle`, { method: 'POST' })
      .then(r => r.json())
      .then(() => loadSoar());
  }

  function testVirusTotal() {
    const out = document.getElementById('soar-vt-test-result');
    if (out) {
      out.className = 'small px-2 pb-2 text-muted';
      out.textContent = 'EICAR 테스트 해시 조회 중…';
    }
    const hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    fetch('/api/soar/virustotal/test', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({hash}),
    }).then(async r => ({ok:r.ok, body:await r.json()})).then(({ok, body}) => {
      if (out) {
        out.className = 'small px-2 pb-2 ' + (ok ? 'text-success' : 'text-danger');
        out.innerHTML = ok
          ? `<i class="fa fa-circle-check me-1"></i>${escapeHtml(body.verdict || body.status)} · 악성 ${body.malicious || 0} · 의심 ${body.suspicious || 0}${body.cached ? ' · 캐시' : ''}`
          : `<i class="fa fa-circle-xmark me-1"></i>${escapeHtml(body.error || body.status || '조회 실패')}`;
      }
      loadSoar();
    }).catch(() => {
      if (out) { out.className = 'small px-2 pb-2 text-danger'; out.textContent = '연결 테스트 요청 실패'; }
    });
  }

  function soarManualBlock() {
    const input = document.getElementById('soar-block-ip-input');
    const ip = (input?.value || '').trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) { alert('올바른 IPv4 주소를 입력하세요'); return; }
    fetch('/api/soar/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }).then(r => r.json()).then(d => {
      if (input) input.value = '';
      loadSoar();
      if (!d.success) alert(d.message || '차단 실패');
    });
  }

  function soarUnblock(ip) {
    fetch('/api/soar/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }).then(() => loadSoar());
  }

  /* ════════════════════ ML 의사결정 지원 ════════════════════ */
  const DS_RECO_BADGES = {
    BLOCK:    '<span class="badge bg-danger">차단 권고</span>',
    FP_TUNE:  '<span class="badge bg-warning text-dark">오탐 튜닝</span>',
    CAMPAIGN: '<span class="badge bg-orange">캠페인 의심</span>',
    REVIEW:   '<span class="badge bg-info text-dark">수동 검토</span>',
    MONITOR:  '<span class="badge bg-secondary">관찰</span>',
  };

  function loadDecisionSupport() {
    fetch('/api/ml/decision')
      .then(r => r.json())
      .then(renderDecisionSupport)
      .catch(() => {});
  }

  function renderDecisionSupport(d) {
    const cEl = document.getElementById('ds-cluster-count');
    if (cEl) cEl.textContent = `${d.cluster_count || 0} 그룹`;
    const vEl = document.getElementById('ds-verdict-count');
    if (vEl) vEl.textContent = `판정 ${d.total_verdicts || 0}건 (오탐 ${d.total_fp || 0})`;

    const tbody = document.getElementById('ds-clusters-tbody');
    if (!tbody) return;
    const rows = (d.clusters || []).map(c => {
      const rate = c.tp_rate == null ? '-' : `${Math.round(c.tp_rate * 100)}%`;
      const rateCls = c.tp_rate == null ? 'text-muted'
                    : c.tp_rate >= 0.7 ? 'text-danger'
                    : c.tp_rate <= 0.3 ? 'text-success' : 'text-warning';
      return `
        <tr>
          <td class="small" style="color:${threatColor(c.threat_type)};font-weight:600">${escapeHtml(c.threat_type)}</td>
          <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(c.src_net)}</td>
          <td class="small" style="color:#e6edf3">${c.count}</td>
          <td class="small" style="color:#e6edf3">${c.unique_ips}</td>
          <td class="small">${sevBadge(c.dominant_severity)}</td>
          <td class="small" style="color:#e6edf3">${c.tp} / ${c.fp}</td>
          <td class="small ${rateCls}">${rate}</td>
          <td class="small">${DS_RECO_BADGES[c.recommendation] || ''}
            <span style="color:#e6edf3" title="${escapeHtml(c.reason)}">${escapeHtml(c.reason)}</span></td>
        </tr>`;
    }).join('');
    tbody.innerHTML = rows || '<tr><td colspan="8" class="text-muted text-center p-3">아직 그룹 없음</td></tr>';
  }

  socket.on('decision_update', d => {
    if (!document.getElementById('panel-ml')?.classList.contains('d-none')) {
      renderDecisionSupport(d);
    }
  });

  /* ════════════════════ 인시던트 케이스 관리 ════════════════════ */
  let selectedIncidentId = null;

  const INC_STATUS_BADGES = {
    OPEN:          '<span class="badge bg-danger">OPEN</span>',
    INVESTIGATING: '<span class="badge bg-warning text-dark">INVESTIGATING</span>',
    CONTAINED:     '<span class="badge bg-info text-dark">CONTAINED</span>',
    RESOLVED:      '<span class="badge bg-success">RESOLVED</span>',
  };
  const INC_TL_ICONS = {
    open:   '<i class="fa fa-folder-plus text-danger"></i>',
    alert:  '<i class="fa fa-triangle-exclamation text-warning"></i>',
    block:  '<i class="fa fa-ban text-danger"></i>',
    status: '<i class="fa fa-arrows-rotate text-cyan"></i>',
    assign: '<i class="fa fa-user text-info"></i>',
    note:   '<i class="fa fa-pen text-secondary"></i>',
    enrich: '<i class="fa fa-shield-virus text-purple"></i>',
  };

  function loadIncidents() {
    fetch('/api/incidents')
      .then(r => r.json())
      .then(renderIncidents)
      .catch(() => {});
  }

  let _priorityReloadTimer = null;
  function schedulePriorityReload() {
    if (_priorityReloadTimer) return;
    _priorityReloadTimer = setTimeout(() => {
      _priorityReloadTimer = null;
      if (isPanelVisible('overview')) loadPriorityQueue();
    }, 800);
  }

  function loadPriorityQueue() {
    Promise.all([
      fetch('/api/incidents?limit=8').then(r => r.json()),
      fetch('/api/alerts/groups?hours=24&min_count=2&limit=8').then(r => r.json()),
    ]).then(([incData, groupData]) => {
      const incBox = document.getElementById('overview-active-incidents');
      const active = (incData.incidents || []).filter(i =>
        i.status === 'OPEN' || i.status === 'INVESTIGATING').slice(0, 5);
      if (incBox) incBox.innerHTML = active.length ? active.map(i => `
        <div class="priority-item" onclick="showPanel('incidents'); selectIncident(${i.id})">
          <div>
            <div class="priority-title">#${i.id} ${escapeHtml(i.title)}</div>
            <div class="priority-meta">${escapeHtml(i.status)} · ${escapeHtml(i.assignee || '미배정')} · ${escapeHtml((i.updated || '').slice(5))}</div>
          </div>
          <div class="priority-count">${sevBadge(i.severity)} · ${i.alert_count}건</div>
        </div>`).join('') : '<div class="text-success p-3 small text-center">처리 대기 인시던트 없음</div>';

      const groupBox = document.getElementById('overview-alert-groups');
      const groups = groupData.groups || [];
      if (groupBox) groupBox.innerHTML = groups.length ? groups.map(g => `
        <div class="priority-item" onclick="openAlertGroup('${escapeHtml(g.src_ip)}','${escapeHtml(g.threat_type)}')">
          <div>
            <div class="priority-title font-monospace">${escapeHtml(g.src_ip)} · ${escapeHtml(g.threat_label)}</div>
            <div class="priority-meta">최종 ${escapeHtml((g.last_seen || '').slice(5))} · 미처리 ${g.open_count}건</div>
          </div>
          <div class="priority-count">${sevBadge(g.severity)} · ${g.count}회</div>
        </div>`).join('') : '<div class="text-success p-3 small text-center">반복 공격 그룹 없음</div>';
    }).catch(() => {});
  }

  function renderIncidents(d) {
    const stats = d.stats || {};
    const set = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = (v ?? 0).toLocaleString();
    };
    set('inc-active', stats.active);
    set('inc-investigating', stats.investigating);
    set('inc-contained', stats.contained);
    set('inc-resolved', stats.resolved);
    set('sidebar-inc-count', stats.active);
    setPipe('pipe-inc-active', stats.active);

    const tbody = document.getElementById('inc-tbody');
    if (!tbody) return;
    const rows = (d.incidents || []).map(inc => `
      <tr style="cursor:pointer" onclick="selectIncident(${inc.id})"
          ${inc.id === selectedIncidentId ? 'class="table-active"' : ''}>
        <td class="small text-cyan">#${inc.id}</td>
        <td class="small" style="color:#e6edf3">${escapeHtml(inc.title)}</td>
        <td class="small">${sevBadge(inc.severity)}</td>
        <td class="small">${INC_STATUS_BADGES[inc.status] || escapeHtml(inc.status)}</td>
        <td class="small" style="color:#e6edf3">${inc.alert_count}</td>
        <td class="small" style="color:#e6edf3">${escapeHtml(inc.assignee || '-')}</td>
        <td class="small text-muted" style="white-space:nowrap">${escapeHtml((inc.updated || '').slice(5))}</td>
      </tr>`).join('');
    tbody.innerHTML = rows || '<tr><td colspan="7" class="text-muted text-center p-3">인시던트 없음</td></tr>';

    if (selectedIncidentId) loadIncidentDetail(selectedIncidentId);
  }

  function selectIncident(id) {
    selectedIncidentId = id;
    loadIncidentDetail(id);
    loadIncidents();
  }

  function loadIncidentDetail(id) {
    fetch(`/api/incidents/${id}`)
      .then(r => r.json())
      .then(inc => {
        if (inc.error) return;
        const title = document.getElementById('inc-detail-title');
        if (title) title.textContent = `#${inc.id} ${inc.title}`;
        const controls = document.getElementById('inc-detail-controls');
        if (controls) controls.classList.remove('d-none');
        const sel = document.getElementById('inc-status-select');
        if (sel) sel.value = inc.status;
        const asg = document.getElementById('inc-assignee-input');
        if (asg) asg.value = inc.assignee || '';

        const box = document.getElementById('inc-timeline');
        if (box) {
          box.innerHTML = [...(inc.timeline || [])].reverse().map(t => `
            <div class="d-flex gap-2 p-2 border-bottom border-secondary small">
              <span>${INC_TL_ICONS[t.kind] || ''}</span>
              <span class="text-muted" style="white-space:nowrap; font-size:10px">${escapeHtml((t.ts || '').slice(5))}</span>
              <span style="color:#e6edf3">${escapeHtml(t.text)}</span>
            </div>`).join('') || '<div class="text-muted p-3 small">타임라인 없음</div>';
        }
      });
  }

  function saveIncident() {
    if (!selectedIncidentId) return;
    const status = document.getElementById('inc-status-select')?.value;
    const assignee = document.getElementById('inc-assignee-input')?.value ?? '';
    const noteInput = document.getElementById('inc-note-input');
    const note = (noteInput?.value || '').trim();
    fetch(`/api/incidents/${selectedIncidentId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, assignee, note: note || undefined }),
    }).then(() => {
      if (noteInput) noteInput.value = '';
      loadIncidents();
    });
  }

  socket.on('incident_update', d => {
    const badge = document.getElementById('sidebar-inc-count');
    if (badge && d.stats) badge.textContent = (d.stats.active || 0).toLocaleString();
    if (d.stats) setPipe('pipe-inc-active', d.stats.active);
    if (!document.getElementById('panel-incidents')?.classList.contains('d-none')) {
      renderIncidents(d);
    }
    schedulePriorityReload();
  });

  const SOAR_LIVE_LABEL = {
    block_ip: '🚫 IP 차단', unblock: '해제', auto_close: '✓ 오탐 자동종결',
    escalate: '▲ 정탐 에스컬레이션', triage: 'AI 트리아지', incident: '📁 인시던트 승격',
  };

  socket.on('soar_action', a => {
    const badge = document.getElementById('sidebar-soar-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g, '')) || 0) + 1).toLocaleString();
    // 파이프라인 즉시 반영
    incPipe('pipe-soar-actions');
    if (a.action === 'block_ip') incPipe('pipe-soar-blocked');
    if (a.action === 'auto_close') { incPipe('pipe-ai-fp'); incPipe('pipe-ai-triage'); }
    if (a.action === 'escalate') { incPipe('pipe-ai-tp'); incPipe('pipe-ai-triage'); }
    // 통합 라이브 스트림 (해제/트리아지 제외 — 핵심 대응만)
    if (!['unblock', 'triage'].includes(a.action)) {
      const sev = a.action === 'block_ip' ? 'critical'
                : a.action === 'escalate' ? 'high'
                : a.action === 'incident' ? 'high' : 'info';
      pushLive('soar', sev,
        `<b>${SOAR_LIVE_LABEL[a.action] || escapeHtml(a.action)}</b> ` +
        `<span class="lv-ip">${escapeHtml(a.target)}</span> ` +
        `<span class="pb-tag">${escapeHtml(a.playbook)}</span>`);
    }
    const tbody = document.getElementById('soar-actions-tbody');
    if (tbody && !document.getElementById('panel-soar').classList.contains('d-none')) {
      loadSoar();   // 패널 열려 있을 때만 전체 갱신 (KPI/차단목록 동기화)
    }
  });

  function incPipe(id) {
    const el = document.getElementById(id);
    if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g, '')) || 0) + 1).toLocaleString();
  }

  /* ════════════════════ 초기화 ════════════════════ */
  document.addEventListener('DOMContentLoaded', () => {
    showPanel('overview');

    // 데모 모드 표시 (합성 데이터임을 명시)
    fetch('/api/whoami')
      .then(r => r.json())
      .then(d => {
        if (d.demo) document.getElementById('demo-badge')?.classList.remove('d-none');
      })
      .catch(() => {});

    // 초기 데이터 로드
    fetch('/api/dashboard/summary')
      .then(r => r.json())
      .then(d => {
        document.getElementById('stat-total-alerts').textContent = d.threats.total_alerts;
        setOpenAlerts(d.threats.open || 0);
        document.getElementById('stat-total-packets').textContent = d.packets.total_packets.toLocaleString();
        document.getElementById('stat-sysmon-events').textContent = d.sysmon.total_events.toLocaleString();
        document.getElementById('stat-ai-analyses').textContent   = d.ai.total_analyses;
      });

    // 초기 알림 + 개요 KPI 채우기
    fetch('/api/alerts?limit=200')
      .then(r => r.json())
      .then(d => {
        (d.alerts || []).slice(0, 5).forEach(a => prependOverviewAlert(a));
        let crit = 0, high = 0, closed = 0, open = 0;
        (d.alerts || []).forEach(a => {
          if (a.severity === 'CRITICAL') crit++;
          if (a.severity === 'HIGH') high++;
          if (a.status === 'CLOSED') closed++;
          if (a.status === 'OPEN')   open++;
          trackAttacker(a.src_ip, a.threat_type);
          _threatTypeCounter[a.threat_label] = (_threatTypeCounter[a.threat_label] || 0) + 1;
        });
        document.getElementById('kpi-critical').textContent = crit;
        document.getElementById('kpi-high').textContent = high;
        document.getElementById('kpi-blocked').textContent = closed;
        document.getElementById('kpi-unique-attackers').textContent = uniqueAttackerCount();
        setOpenAlerts(open);  // 미처리 알림만 사이드바 배지에 반영
        renderTopAttackers();
        renderThreatTypeChart();
        updateThreatLevel();
      });

    // 위협 인텔리전스 초기 상태
    loadThreatIntel();
    loadSiem();
    loadAuthlog();
    loadSoar();
    loadIncidents();
    loadPriorityQueue();

    // 마지막 갱신 시간 표시
    setInterval(() => {
      if (document.hidden || !isPanelVisible('overview')) return;
      const el = document.getElementById('overview-last-update');
      if (el) el.textContent = '최종 갱신 ' + new Date().toLocaleTimeString('ko-KR', { hour12:false });
    }, 1000);

  });

  /* 이 파일이 다른 파일·인라인 핸들러에 공개하는 이름.
     여기 없는 것은 파일 밖에서 보이지 않는다. */
  Object.assign(window, {
    approveAllSoar, loadBlockDecisions, loadDecisionSupport, loadIncidents, loadSoar,
    replayBlockDecision, retrySoarExecution, reviewSoarApproval, saveIncident,
    schedulePriorityReload, selectIncident, showBlockDecision, showVerdictDetail,
    soarManualBlock, soarTogglePb, soarUnblock, testVirusTotal,
  });
})();
