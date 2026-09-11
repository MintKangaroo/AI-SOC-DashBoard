/* Managed identities are an opt-in server feature; no client-stored credentials. */
(function () {
  let accessUsers = [], accessOperation = null, accessBusy = false;
  const accessRoleLabels = {viewer:'뷰어',analyst:'분석가',responder:'대응자',admin:'관리자',administrator:'관리자'};
  function accessRoleLabel(role) { return accessRoleLabels[role] || role; }
  async function loadAccess() {
    if (!document.getElementById('access-status')) return;
    try {
      const status = await SOCUI.request('/api/identity');
      document.getElementById('access-status').textContent = {managed:'관리 모드 · 로컬 사용자와 회수 가능한 서버 세션. SSO 는 설정되지 않았습니다.',single_admin:'단일 관리자 · 기존 DASH 자격 증명. 관리 사용자는 AUTH_USERS_DB 설정 후 재기동해야 합니다.',auth_disabled:'인증 꺼짐 · 제한 없는 접근. 역할 검사와 관리 사용자는 사용할 수 없습니다.'}[status.mode];
      document.getElementById('access-password-section').hidden = status.mode !== 'managed';
      if (!SOCAccess.can('admin')) return;
      const [users,audit] = await Promise.all([SOCUI.request('/api/identity/users'),SOCUI.request('/api/identity/audit')]);
      accessUsers = users.users;
      document.getElementById('access-create').disabled = status.mode !== 'managed';
      document.getElementById('access-users').innerHTML = users.users.map(user => `<tr><td>${escapeHtml(user.username)}</td><td>${escapeHtml(accessRoleLabel(user.role))}</td><td>${user.active ? '활성' : '비활성'}</td><td>${escapeHtml(new Date(user.updated*1000).toLocaleString())}</td><td><button class="btn btn-xs btn-outline-secondary" ${act('accessOpenUser',['edit',user.username])}>권한 편집</button> <button class="btn btn-xs btn-outline-secondary" ${act('accessOpenUser',['revoke',user.username])}>세션 회수</button></td></tr>`).join('') || '<tr><td colspan="5" class="console-empty">관리 사용자 디렉터리가 비활성입니다. 기존 관리자 접근은 유지됩니다.</td></tr>';
      document.getElementById('access-audit').innerHTML = audit.events.map(event => `<div class="console-case"><strong>${escapeHtml(event.action)} · ${escapeHtml(event.target)}</strong><small>${escapeHtml(event.actor)} · ${escapeHtml(new Date(event.ts*1000).toLocaleString())}</small><p>${escapeHtml(event.detail)}</p></div>`).join('') || '<p>계정 관리 이벤트 없음.</p>';
    } catch (error) { document.getElementById('access-status').textContent = error.message; }
  }
  function accessOpenUser(operation, username) {
    accessOperation = operation;
    const user = accessUsers.find(value => value.username === username);
    document.getElementById('access-form').reset();
    document.getElementById('access-error').textContent = '';
    document.getElementById('access-dialog-title').textContent = {create:'관리 사용자 생성',edit:'권한 변경 · 세션 회수',revoke:'모든 세션 회수'}[operation];
    const name = document.getElementById('access-username'); name.value = username || ''; name.readOnly = operation !== 'create';
    document.getElementById('access-new-role').value = user?.role || 'viewer';
    document.getElementById('access-active').checked = user ? Boolean(user.active) : true;
    document.getElementById('access-active').closest('label').hidden = operation === 'create';
    document.getElementById('access-role-fields').hidden = operation === 'revoke';
    document.getElementById('access-new-password').required = operation === 'create';
    document.getElementById('access-dialog').showModal();
  }
  function accessCloseUser() {
    if (accessBusy) return;
    document.getElementById('access-dialog').close(); document.getElementById('access-form').reset();
  }
  async function accessSaveUser(event) {
    event.preventDefault();
    if (accessBusy || !accessOperation) return;
    accessBusy = true; document.getElementById('access-submit').disabled = true;
    const username = document.getElementById('access-username').value;
    const body = {current_password:document.getElementById('access-confirm-password').value,reason:document.getElementById('access-reason').value.trim()};
    if (accessOperation === 'revoke') body.revoke = true;
    else {
      body.role = document.getElementById('access-new-role').value;
      const password = document.getElementById('access-new-password').value;
      if (password) body.password = password;
      if (accessOperation === 'create') body.username = username;
      else body.active = document.getElementById('access-active').checked;
    }
    try {
      const result = await SOCUI.request('/api/identity/users' + (accessOperation === 'create' ? '' : '/' + encodeURIComponent(username)),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      accessBusy = false; accessCloseUser();
      if (result.sign_in_again) { location.assign('/login'); return; }
      SOCUI.notify('계정 변경이 기록되었습니다. 해당되는 기존 세션은 회수되었습니다.'); loadAccess();
    } catch (error) { document.getElementById('access-error').textContent = error.message; }
    finally { accessBusy = false; document.getElementById('access-submit').disabled = false; document.getElementById('access-confirm-password').value = ''; document.getElementById('access-new-password').value = ''; }
  }
  onPanelReady('access',() => {
    document.getElementById('access-password-form').addEventListener('submit',async event => {
      event.preventDefault();
      const button = event.target.querySelector('button[type=submit]'); button.disabled = true;
      try {
        await SOCUI.request('/api/identity/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:document.getElementById('access-own-current').value,password:document.getElementById('access-own-new').value,reason:'본인 비밀번호 변경'})});
        location.assign('/login');
      } catch (error) { document.getElementById('access-password-error').textContent = error.message; }
      finally { button.disabled = false; document.getElementById('access-own-current').value = ''; document.getElementById('access-own-new').value = ''; }
    });
  });
  document.addEventListener('DOMContentLoaded',() => {
    document.getElementById('access-form').addEventListener('submit',accessSaveUser);
    document.getElementById('access-dialog').addEventListener('cancel',event => { if (accessBusy) event.preventDefault(); });
    document.getElementById('access-dialog').addEventListener('close',() => {
      document.getElementById('access-form').reset(); accessOperation = null;
    });
  });
  document.addEventListener('soc:panel',event => { if (event.detail === 'access') loadAccess(); });
  Object.assign(window,{loadAccess,accessOpenUser,accessCloseUser});
})();
