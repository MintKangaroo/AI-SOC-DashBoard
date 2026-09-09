"""Explicit mutation policy. New writes are denied until added to this inventory."""
import threading

from modules.identity import ROLES
from modules.logging_setup import get_logger

_log = get_logger(__name__)

# Endpoint names from the existing Blueprint, not URL-prefix guesses.
_GROUPS = {
    'profile': ['identity_password'],
    'investigate': '''update_alert_status update_alert_verdict check_hash ai_chat analyze_alert
        analyze_traffic ml_analyze ml_feedback ti_check ip_reputation_check watchlist_add
        watchlist_remove watchlist_check hunts_create hunts_update hunts_delete hunts_run
        hunts_promote labeling_label incident_update console_copilot console_preview
        console_siem_query sigma_test report_generate'''.split(),
    'respond': '''soar_retry_execution soar_block soar_review_approval soar_batch_approval
        soar_unblock patch_run patch_command edr_kill'''.split(),
    'scan': '''hash_file yara_scan patch_scan patch_playbook vulnscan_scan fuzz_run fuzz_stop
        purple_run'''.split(),
    'tune': '''sigma_reload sigma_toggle yara_reload dedup_add_rule dedup_delete_rule
        dedup_toggle_rule ml_retrain ti_refresh soar_toggle_playbook'''.split(),
    'admin': '''retention_run alerts_archive notify_test soar_virustotal_test
        identity_create identity_change'''.split(),
}
MUTATION_PERMISSIONS = {('api.' + name):permission for permission,names in _GROUPS.items() for name in names}
ADMIN_READS = {'api.identity_users', 'api.identity_audit'}


def permission_for(endpoint, method):
    if endpoint in ADMIN_READS:
        return 'admin'
    if method in ('GET','HEAD','OPTIONS'):
        return 'read'
    return MUTATION_PERMISSIONS.get(endpoint)


def allowed(principal, permission):
    return bool(principal and permission in ROLES.get(principal.get('role'), ()))


class SocketAccess:
    """Revalidate server-side sessions on inbound commands and every outbound delivery.

    Flask-SocketIO's copied session does not observe HTTP logout by itself. This
    registry stores opaque tokens, never trusts a cached role or client user field.
    Applies only in authenticated mode. No new collectors or background workers.
    """
    def __init__(self, socketio, auth):
        self.socketio, self.auth = socketio, auth
        self._lock, self._clients = threading.RLock(), {}
        self._outage = False
        self._emit = socketio.emit
        socketio.emit = self.emit

    def _principal(self, token):
        try:
            principal = self.auth.principal(token)
            self._outage = False
            return principal
        except Exception:
            if not self._outage:
                _log.error('Identity lookup failed; realtime delivery withheld.')
            self._outage = True
            return None

    def connect(self, sid, token):
        with self._lock:
            self._clients[sid] = token
        if not self._principal(token):
            self.remove(sid)
            return False
        return True

    def remove(self, sid):
        with self._lock:
            self._clients.pop(sid, None)

    def sweep(self):
        with self._lock:
            clients = dict(self._clients)
        for sid, token in clients.items():
            if not self._principal(token):
                self.remove(sid)
                self.socketio.server.disconnect(sid, namespace='/')

    def emit(self, event, *args, **kwargs):
        with self._lock:
            clients = dict(self._clients)
        target = kwargs.get('to') or kwargs.get('room')
        skip = kwargs.get('skip_sid') or []
        skip = [skip] if isinstance(skip, str) else skip
        checked = {}
        for sid, token in clients.items():
            if (target and target != sid) or sid in skip:
                continue
            if token not in checked:
                checked[token] = self._principal(token)
            if checked[token]:
                options = {k:v for k,v in kwargs.items() if k not in ('to','room')}
                self._emit(event, *args, to=sid, **options)
            else:
                self.remove(sid)
                self.socketio.server.disconnect(sid, namespace='/')
