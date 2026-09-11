/* Presentation of server permissions. The Flask gate remains authoritative. */
(function () {
  const permissions = new Set((document.body.dataset.accessPermissions || '').split(','));
  const accessActionGroups = {
    investigate: 'consoleAnalystAction consoleBulkAction consoleAskCopilot consolePreviewSuppression updateAlertStatus setAlertVerdict analyzeTrafficAI triggerMLAnalysis sendFeedback addWatchlist removeWatchlist createHunt deleteHunt promoteHunt saveIncident labelGroup generateReport checkReputation checkThreatIntel siemRunSearch',
    respond: 'reviewSoarApproval approveAllSoar retrySoarExecution soarManualBlock soarUnblock patchRun patchCommand edrKill',
    scan: 'vulnScan fuzzRun fuzzStop patchPlaybook runYaraScan runPurpleAll runPurpleOne',
    tune: 'reloadSigma toggleSigma reloadYara retrainML soarTogglePb refreshThreatIntel',
    admin: 'runArchive notifyTest testVirusTotal accessOpenUser',
  };
  const accessActionPermissions = Object.fromEntries(Object.entries(accessActionGroups).flatMap(([permission,names]) => names.split(' ').map(name => [name,permission])));
  const SOCAccess = {
    role: document.body.dataset.accessRole || 'unavailable',
    enforced: document.body.dataset.authEnabled === 'true',
    can(permission) { return permissions.has(permission); },
    required(el) {
      const name = el.dataset.action || el.dataset.actionChange || el.dataset.actionEnter;
      // A refresh is a read; explicitly requested package discovery is a scan.
      if (name === 'loadPatch') return el.dataset.args?.includes('true') ? 'scan' : null;
      return el.dataset.permission || accessActionPermissions[name];
    },
    apply(root) {
      const selector = '[data-action],[data-action-change],[data-action-enter],[data-permission]';
      const elements = [...(root.matches?.(selector) ? [root] : []), ...(root.querySelectorAll?.(selector) || [])];
      elements.forEach(el => {
        const permission = this.required(el);
        if (permission && !this.can(permission)) {
          el.setAttribute('aria-disabled','true'); el.title = permission + ' 권한이 필요합니다 · 현재 역할: ' + this.role;
          if ('disabled' in el && !el.disabled) el.disabled = true;
          el.classList.add('access-restricted');
        }
      });
    },
  };
  for (const type of ['click','change','keydown']) document.addEventListener(type,event => {
    if (type === 'keydown' && !['Enter',' '].includes(event.key)) return;
    const el = event.target.closest?.('[data-action],[data-action-change],[data-action-enter],[data-permission]');
    const permission = el && SOCAccess.required(el);
    if (permission && !SOCAccess.can(permission)) {
      event.preventDefault(); event.stopImmediatePropagation();
      window.SOCUI?.notify('현재 역할(' + SOCAccess.role + ')로는 이 작업을 할 수 없습니다.');
    }
  },true);
  document.addEventListener('DOMContentLoaded',() => {
    const badge = document.getElementById('access-role-badge');
    if (badge) badge.textContent = SOCAccess.enforced ? SOCAccess.role.toUpperCase() + ' · 서버 검증' : '인증 꺼짐 · 제한 없음';
    const banner = document.getElementById('access-context');
    if (banner) { banner.textContent = SOCAccess.enforced ? '역할: ' + SOCAccess.role + (SOCAccess.role === 'viewer' ? ' · 읽기 전용 조사' : ' · 조치는 서버 권한 검사를 거칩니다') : '인증 꺼짐 · 제한 없는 로컬 접근'; }
    SOCAccess.apply(document.body);
    new MutationObserver(records => records.forEach(record => {
      if (record.type === 'attributes') SOCAccess.apply(record.target);
      else record.addedNodes.forEach(node => { if (node.nodeType === 1) SOCAccess.apply(node); });
    })).observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['disabled']});
  });
  Object.assign(window,{SOCAccess});
})();
