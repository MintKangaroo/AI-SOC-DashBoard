/* Managed identities are an opt-in server feature; no client-stored credentials. */
(function () {
  let accessUsers = [], accessOperation = null, accessBusy = false;
  async function loadAccess() {
    if (!document.getElementById('access-status')) return;
    try {
      const status = await SOCUI.request('/api/identity');
      document.getElementById('access-status').textContent = {managed:'MANAGED · local users and revocable server sessions. SSO is not configured.',single_admin:'SINGLE ADMIN · existing DASH credentials. Managed users require AUTH_USERS_DB and a restart.',auth_disabled:'AUTHENTICATION OFF · unrestricted access. Role enforcement and managed users are unavailable.'}[status.mode];
      document.getElementById('access-password-section').hidden = status.mode !== 'managed';
      if (!SOCAccess.can('admin')) return;
      const [users,audit] = await Promise.all([SOCUI.request('/api/identity/users'),SOCUI.request('/api/identity/audit')]);
      accessUsers = users.users;
      document.getElementById('access-create').disabled = status.mode !== 'managed';
      document.getElementById('access-users').innerHTML = users.users.map(user => `<tr><td>${escapeHtml(user.username)}</td><td>${escapeHtml(user.role)}</td><td>${user.active ? 'ENABLED' : 'DISABLED'}</td><td>${escapeHtml(new Date(user.updated*1000).toLocaleString())}</td><td><button class="btn btn-xs btn-outline-secondary" ${act('accessOpenUser',['edit',user.username])}>Edit access</button> <button class="btn btn-xs btn-outline-secondary" ${act('accessOpenUser',['revoke',user.username])}>Revoke sessions</button></td></tr>`).join('') || '<tr><td colspan="5" class="console-empty">Managed identity directory is not enabled. Existing administrator access is preserved.</td></tr>';
      document.getElementById('access-audit').innerHTML = audit.events.map(event => `<div class="console-case"><strong>${escapeHtml(event.action)} · ${escapeHtml(event.target)}</strong><small>${escapeHtml(event.actor)} · ${escapeHtml(new Date(event.ts*1000).toLocaleString())}</small><p>${escapeHtml(event.detail)}</p></div>`).join('') || '<p>No identity administration events recorded.</p>';
    } catch (error) { document.getElementById('access-status').textContent = error.message; }
  }
  function accessOpenUser(operation, username) {
    accessOperation = operation;
    const user = accessUsers.find(value => value.username === username);
    document.getElementById('access-form').reset();
    document.getElementById('access-error').textContent = '';
    document.getElementById('access-dialog-title').textContent = {create:'Create managed user',edit:'Change access and revoke sessions',revoke:'Revoke all sessions'}[operation];
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
      SOCUI.notify('Identity change recorded. Previous sessions were revoked where applicable.'); loadAccess();
    } catch (error) { document.getElementById('access-error').textContent = error.message; }
    finally { accessBusy = false; document.getElementById('access-submit').disabled = false; document.getElementById('access-confirm-password').value = ''; document.getElementById('access-new-password').value = ''; }
  }
  onPanelReady('access',() => {
    document.getElementById('access-password-form').addEventListener('submit',async event => {
      event.preventDefault();
      const button = event.target.querySelector('button[type=submit]'); button.disabled = true;
      try {
        await SOCUI.request('/api/identity/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:document.getElementById('access-own-current').value,password:document.getElementById('access-own-new').value,reason:'Self-service password change'})});
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
