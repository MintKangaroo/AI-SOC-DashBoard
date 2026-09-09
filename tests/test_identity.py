"""Managed identities: no escalation, revocable sessions and atomic administration."""
import json
import sqlite3
from types import SimpleNamespace

import pytest
from flask import Flask

from api.routes import api_bp
from modules.auth import AuthManager
from modules.authorization import MUTATION_PERMISSIONS, allowed, permission_for
from modules.identity import IdentityStore, ROLES
from tests.test_api_error_handling import app_module  # noqa: F401

PASSWORD = 'Temporary-Test-Only-Password-42!'
ORIGIN = {'Origin':'http://localhost'}


@pytest.fixture
def directory(tmp_path):
    store = IdentityStore(str(tmp_path/'users.db'))
    store.create('owner', PASSWORD, 'admin', actor='test-provisioner', reason='Isolated fixture')
    yield store
    store.close()


@pytest.mark.parametrize('role', sorted(ROLES))
def test_role_credentials_are_server_side_and_not_exported(directory, role):
    directory.create('test-user', PASSWORD, role, actor='test-provisioner', reason='Fixture')
    auth = AuthManager('unused', user_store=directory)
    token, reason = auth.login('test-user', PASSWORD, '127.0.0.1', 60)
    assert reason == 'ok' and auth.principal(token)['role'] == role
    public = json.dumps(directory.list_users()) + json.dumps(directory.audit())
    assert PASSWORD not in public and 'password_hash' not in public and token not in public
    assert not auth.verify('test-user', 'wrong', '127.0.0.1')[0]


def test_session_is_expired_rotated_and_revocable(directory):
    auth = AuthManager('unused', user_store=directory)
    old, _ = auth.login('owner', PASSWORD, 'x', 60)
    expired, _ = auth.login('owner', PASSWORD, 'x', -1)
    assert auth.principal(expired) is None
    directory.change('owner', actor='local-recovery', reason='Rotate password', password=PASSWORD+'new')
    assert auth.principal(old) is None
    assert not auth.verify('owner', PASSWORD, 'x')[0]
    fresh, _ = auth.login('owner', PASSWORD+'new', 'x', 60)
    assert auth.principal(fresh)
    auth.revoke(fresh)
    assert auth.principal(fresh) is None


def test_password_check_race_cannot_issue_session_after_reset(directory):
    record = directory.credentials('owner')
    directory.change('owner', actor='local-recovery', reason='Race regression', revoke=True)
    assert directory.issue('owner', record['version'], 60) is None


def test_last_admin_self_demotion_and_stale_admin_are_protected(directory):
    principal = {'username':'owner','role':'admin','version':1}
    with pytest.raises(ValueError):
        directory.change('owner', actor=principal, reason='Self demotion', role='viewer')
    with pytest.raises(ValueError):
        directory.change('owner', actor='local-recovery', reason='Last admin', active=False)
    directory.create('another-admin', PASSWORD, 'admin', actor=principal, reason='Additional admin')
    directory.change('owner', actor='local-recovery', reason='Session change', revoke=True)
    with pytest.raises(PermissionError):
        directory.create('stale-session-user', PASSWORD, 'admin', actor=principal, reason='Stale request')


def test_admin_write_and_audit_are_atomic(directory):
    directory._conn.execute("CREATE TRIGGER reject_identity_audit BEFORE INSERT ON identity_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError):
        directory.create('not-created', PASSWORD, 'analyst', actor='test-provisioner', reason='Audit failure')
    assert directory.get('not-created') is None


def test_legacy_login_also_requires_server_session():
    auth = AuthManager('legacy', password=PASSWORD)
    token, _ = auth.login('legacy', PASSWORD, 'x', 60)
    assert auth.principal(token)['role'] == 'admin'
    assert auth.principal('fabricated') is None
    auth.revoke(token)
    assert auth.principal(token) is None


def test_all_mutations_have_explicit_non_stale_policy():
    app = Flask(__name__)
    app.register_blueprint(api_bp, url_prefix='/api')
    writes = {r.endpoint for r in app.url_map.iter_rules() if r.methods & {'POST','PUT','DELETE','PATCH'}}
    assert writes == set(MUTATION_PERMISSIONS)
    assert not allowed({'role':'admin'}, permission_for('api.future_dangerous_endpoint', 'POST'))
    assert not allowed({'role':'owner'}, 'read')


@pytest.fixture
def secured(app_module, monkeypatch, tmp_path):  # noqa: F811
    # Reuse the isolated import fixture; no live collector/response work in this app.
    monkeypatch.setattr(app_module.config.Config, 'AUTH_ENABLED', True)
    monkeypatch.setattr(app_module.config.Config, 'AUTH_USERS_DB', str(tmp_path/'users.db'))
    monkeypatch.setattr(app_module.config.Config, 'DASH_USERNAME', 'owner')
    monkeypatch.setattr(app_module.config.Config, 'DASH_PASSWORD', PASSWORD)
    monkeypatch.setattr(app_module.config.Config, 'DASH_PASSWORD_HASH', '')
    def wire(app, socketio):
        from modules.audit_log import AuditLog
        app.audit = AuditLog(str(tmp_path/'audit.db'))
        app.ai_analyst = SimpleNamespace(chat=lambda message, context: 'Recorded advisory')
        app.threat_detector = SimpleNamespace(update_alert_status=lambda *args,**kwargs: True)
    monkeypatch.setattr(app_module, 'build_services', wire)
    monkeypatch.setattr(app_module, 'start_services', lambda *args: None)
    app, io = app_module.create_app()
    app.config['TESTING'] = True
    for role in ('viewer','analyst','responder'):
        app.auth.user_store.create(role, PASSWORD, role, actor='test-provisioner', reason='Role fixture')
    yield app, io
    app.auth.user_store.close()
    app.audit.close()


def sign_in(app, username='owner'):
    client = app.test_client()
    response = client.post('/login', data={'username':username,'password':PASSWORD}, headers=ORIGIN)
    assert response.status_code == 302
    return client


@pytest.mark.parametrize('role', ['viewer','analyst','responder'])
def test_forbidden_routes_never_reach_security_actions(secured, role):
    app, _ = secured
    client = sign_in(app, role)
    for rule in app.url_map.iter_rules():
        for method in rule.methods & {'POST','PUT','DELETE','PATCH'}:
            if not rule.endpoint.startswith('api.') or allowed({'role':role},permission_for(rule.endpoint,method)):
                continue
            path = rule.rule
            import re
            path = re.sub(r'<int:[^>]+>', '1', path)
            path = re.sub(r'<[^>]+>', 'owner', path)
            response = client.open(path, method=method, json={}, headers=ORIGIN)
            assert response.status_code == 403, (role,rule.endpoint,response.status_code)
    assert client.get('/api/identity/users').status_code == 403


def test_forged_role_username_and_unsigned_cookie_do_not_escalate(secured):
    app, _ = secured
    client = sign_in(app, 'viewer')
    with client.session_transaction() as session:
        session['role'] = 'admin'
        session['user'] = 'owner'
    assert client.get('/api/whoami').json['role'] == 'viewer'
    assert client.post('/api/soar/block', json={'ip':'8.8.4.4'}, headers=ORIGIN).status_code == 403
    forged = app.test_client()
    with forged.session_transaction() as session:
        session['user'] = 'owner'
        session['role'] = 'admin'
    assert forged.get('/api/whoami').status_code == 401


def test_admin_change_needs_reauthentication_and_revokes_http_and_socket(secured):
    app, io = secured
    admin, viewer = sign_in(app), sign_in(app,'viewer')
    socket = io.test_client(app, flask_test_client=viewer)
    assert socket.is_connected()
    io.emit('test_evidence', {'provenance':'DEMO'})
    assert socket.get_received()[0]['name'] == 'test_evidence'
    payload = {'active':False,'reason':'Access removed','current_password':'wrong'}
    assert admin.post('/api/identity/users/viewer', json=payload, headers=ORIGIN).status_code == 403
    payload['current_password'] = PASSWORD
    assert admin.post('/api/identity/users/viewer', json=payload, headers=ORIGIN).status_code == 200
    assert not socket.is_connected()
    assert viewer.get('/api/whoami').status_code == 401
    assert not io.test_client(app, flask_test_client=viewer).is_connected()
    events = admin.get('/api/identity/audit').json['events']
    assert events[0]['target'] == 'viewer' and PASSWORD not in json.dumps(events)


def test_logout_is_csrf_protected_and_cookie_replay_is_invalid(secured):
    app, io = secured
    client = sign_in(app)
    copied = client.get_cookie('session').value
    socket = io.test_client(app, flask_test_client=client)
    assert client.get('/logout').status_code == 200
    assert client.get('/api/whoami').status_code == 200
    assert client.post('/logout').status_code == 403
    assert client.post('/logout', headers=ORIGIN).status_code == 302
    assert not socket.is_connected()
    replay = app.test_client()
    replay.set_cookie('session', copied)
    assert replay.get('/api/whoami').status_code == 401


def test_socket_commands_enforce_current_role_and_expiry(secured):
    app, io = secured
    viewer = io.test_client(app, flask_test_client=sign_in(app,'viewer'))
    analyst = io.test_client(app, flask_test_client=sign_in(app,'analyst'))
    assert viewer.emit('chat_message', {'message':'Review evidence'}, callback=True)['accepted'] is False
    analyst.emit('chat_message', {'message':'Review evidence'})
    assert analyst.get_received()[0]['name'] == 'chat_response'
    app.auth.user_store.change('analyst', actor='local-recovery', reason='Revocation from another process', revoke=True)
    io.emit('private_evidence', {'record':1})
    assert not analyst.is_connected()
    viewer.disconnect()


def test_viewer_can_change_only_own_password(secured):
    app, _ = secured
    client = sign_in(app, 'viewer')
    payload = {'current_password':PASSWORD,'password':PASSWORD+'new','reason':'Self service'}
    assert client.post('/api/identity/password', json={**payload,'role':'admin'}, headers=ORIGIN).status_code == 400
    assert client.post('/api/identity/password', json=payload, headers=ORIGIN).status_code == 200
    assert client.get('/api/whoami').status_code == 401
    assert app.auth.user_store.get('viewer')['role'] == 'viewer'


def test_identity_api_rejects_untyped_role_and_null_change(secured):
    app, _ = secured
    client = sign_in(app)
    body = {'current_password':PASSWORD, 'reason':'Validation regression', 'role':['admin']}
    assert client.post('/api/identity/users/viewer', json=body, headers=ORIGIN).status_code == 400
    body['role'] = None
    assert client.post('/api/identity/users/viewer', json=body, headers=ORIGIN).status_code == 400
    assert app.auth.user_store.get('viewer')['role'] == 'viewer'


def test_saved_hunt_get_is_preview_and_post_is_authorized_write(secured):
    app, _ = secured
    calls = []
    def run(hunt_id, limit, mark):
        calls.append(mark)
        return {'marked':mark}
    app.hunt_store = SimpleNamespace(run=run)
    # The app's existing hunt service name is resolved by its Blueprint helper.
    app.hunts = app.hunt_store
    viewer = sign_in(app, 'viewer')
    assert viewer.get('/api/hunts/1/run?mark=1').json['marked'] is False
    assert viewer.post('/api/hunts/1/run', headers=ORIGIN).status_code == 403
    analyst = sign_in(app, 'analyst')
    assert analyst.post('/api/hunts/1/run', headers=ORIGIN).json['marked'] is True
    assert calls == [False,True]


def test_identity_outage_withholds_delivery_without_breaking_emit(secured, monkeypatch, caplog):
    app, io = secured
    socket = io.test_client(app, flask_test_client=sign_in(app,'viewer'))
    def unavailable(token):
        raise RuntimeError('Do not disclose internal identity error')
    monkeypatch.setattr(app.auth, 'principal', unavailable)
    io.emit('detected_evidence', {'provenance':'DEMO'})
    assert not socket.is_connected()
    assert 'Do not disclose internal identity error' not in caplog.text


def test_engineio_handshake_enforces_origin_even_with_valid_cookie(secured):
    app, io = secured
    client = sign_in(app, 'viewer')
    path = '/socket.io/?EIO=4&transport=polling'
    for origin in ('https://untrusted.invalid', 'http://localhost:9999'):
        assert client.get(path, headers={'Origin':origin}).status_code == 400
    response = client.get(path, headers=ORIGIN)
    assert response.status_code == 200
    handshake = json.loads(response.data.decode()[1:])
    # No polling client remains to consume a CLOSE packet in this HTTP-only test.
    io.server.eio.sockets.pop(handshake['sid']).close(wait=False)
