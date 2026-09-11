"""Managed local identities. Passwords never appear in responses or audit details."""
from flask import current_app, g, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden, ServiceUnavailable

from api._common import api_bp
from modules.identity import ROLES


def _directory():
    auth = current_app.auth
    if not current_app.config.get('AUTH_ENABLED') or not auth.user_store:
        raise ServiceUnavailable('관리 사용자 기능을 쓸 수 없습니다. AUTH_USERS_DB 를 설정하고 인증을 켜세요.')
    return auth.user_store


def _change_request(allowed_fields):
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) - set(allowed_fields) - {'reason','current_password'}:
        raise BadRequest('Invalid identity request fields.')
    if not isinstance(body.get('reason'), str) or not 3 <= len(body['reason'].strip()) <= 500:
        raise BadRequest('A reason of 3–500 characters is required.')
    if not isinstance(body.get('current_password'), str):
        raise BadRequest('현재 비밀번호를 입력하세요.')
    ok, _ = current_app.auth.verify(g.principal['username'], body['current_password'], request.remote_addr or '?')
    if not ok:
        raise Forbidden('비밀번호 확인에 실패했거나 로그인 시도가 일시 제한되었습니다.')
    return body


@api_bp.get('/identity')
def identity_status():
    auth = current_app.auth
    return jsonify({'mode':'managed' if auth.user_store else 'single_admin' if current_app.config.get('AUTH_ENABLED') else 'auth_disabled',
                    'roles':{role:sorted(permissions) for role,permissions in ROLES.items()},
                    'sso':'UNAVAILABLE', 'session_policy':'절대 만료 · 서버측 회수 · 브라우저 쿠키의 역할 주장 불신.'})


@api_bp.get('/identity/users')
def identity_users():
    store = current_app.auth.user_store
    return jsonify({'users':store.list_users() if store else [], 'managed':bool(store)})


@api_bp.get('/identity/audit')
def identity_audit():
    store = current_app.auth.user_store
    return jsonify({'events':store.audit() if store else [], 'scope':'최근 계정 관리 이벤트 100건 · 변경과 이벤트는 원자적으로 커밋.'})


@api_bp.post('/identity/users')
def identity_create():
    store = _directory()
    body = _change_request({'username','password','role'})
    try:
        user = store.create(body.get('username'), body.get('password'), body.get('role'),
                            actor=g.principal, reason=body['reason'].strip())
    except ValueError as error:
        raise BadRequest(str(error)) from None
    except PermissionError as error:
        raise Forbidden(str(error)) from None
    return jsonify({'user':user}), 201


@api_bp.post('/identity/users/<username>')
def identity_change(username):
    store = _directory()
    body = _change_request({'role','active','password','revoke'})
    if not any(key in body for key in ('role','active','password')) and body.get('revoke') is not True:
        raise BadRequest('역할·활성 상태·비밀번호 재설정·세션 회수 중 하나는 지정해야 합니다.')
    if 'revoke' in body and type(body['revoke']) is not bool:
        raise BadRequest('Revoke must be a boolean.')
    if any(key in body and body[key] is None for key in ('role','active','password')):
        raise BadRequest('Change fields cannot be null.')
    try:
        user = store.change(username, actor=g.principal, reason=body['reason'].strip(),
                            **{key:body[key] for key in ('role','active','password','revoke') if key in body})
    except ValueError as error:
        raise BadRequest(str(error)) from None
    except PermissionError as error:
        raise Forbidden(str(error)) from None
    if current_app.socket_access:
        current_app.socket_access.sweep()
    return jsonify({'user':user, 'sessions_revoked':True, 'sign_in_again':username == g.principal['username']})


@api_bp.post('/identity/password')
def identity_password():
    store = _directory()
    body = _change_request({'password'})
    try:
        store.change_password(g.principal, body.get('password'))
    except ValueError as error:
        raise BadRequest(str(error)) from None
    except PermissionError as error:
        raise Forbidden(str(error)) from None
    if current_app.socket_access:
        current_app.socket_access.sweep()
    return jsonify({'sign_in_again':True, 'sessions_revoked':True})
