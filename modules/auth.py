"""
대시보드 인증 모듈

- 기존 단일 관리자 호환 + 선택적 로컬 다중 사용자 디렉터리
- 서버에서 회수 가능한 만료 세션; 쿠키의 역할은 신뢰하지 않음
- IP별 로그인 시도 제한(브루트포스 방어) — N회 실패 시 일정 시간 잠금
- 비밀번호는 평문 저장 안 함: Werkzeug 비밀번호 해시로 변환

werkzeug.security(Flask 의존성)만 사용 — 추가 패키지 불필요.
"""
import time
import secrets
import threading

from werkzeug.security import generate_password_hash, check_password_hash


class AuthManager:
    def __init__(self, username, password=None, password_hash=None,
                 max_attempts=5, window=300, lockout=300, user_store=None):
        self.user_store = user_store
        self._sessions = {}
        self._dummy_hash = generate_password_hash(secrets.token_urlsafe(24))
        self.username = username
        if password_hash:
            self.password_hash = password_hash
        elif password:
            self.password_hash = generate_password_hash(password)
        else:
            self.password_hash = None          # 비밀번호 미설정 → 로그인 불가
        self.max_attempts = max_attempts       # window 내 최대 실패 횟수
        self.window = window                   # 실패 집계 구간(초)
        self.lockout = lockout                 # 잠금 시간(초)
        self._lock = threading.Lock()
        self._fails = {}                       # ip → [실패 timestamp]
        self._locked_until = {}                # ip → 잠금 해제 시각

    @property
    def configured(self):
        return bool(self.user_store.list_users()) if self.user_store else bool(self.password_hash)

    def is_locked(self, ip):
        with self._lock:
            return self._locked_until.get(ip, 0) > time.time()

    def lock_remaining(self, ip):
        with self._lock:
            return max(0, int(self._locked_until.get(ip, 0) - time.time()))

    def _validate(self, username, password, ip):
        if self.is_locked(ip):
            return None, "locked"
        if not self.user_store and not self.password_hash:
            return None, "no_password"
        record = None
        if isinstance(username, str) and len(username) <= 64:
            record = self.user_store.credentials(username) if self.user_store else (
                {'username':self.username, 'password_hash':self.password_hash,
                 'role':'admin', 'active':1, 'version':1} if username == self.username else None)
        encoded = record['password_hash'] if record else self._dummy_hash
        # Unknown and disabled users still perform a password check.
        valid_input = isinstance(password, str) and len(password) <= 4096
        try:
            matches = check_password_hash(encoded, password if valid_input else '')
        except (ValueError, TypeError):
            matches = False
        ok = bool(valid_input and matches and record and record['active'])
        with self._lock:
            if ok:
                self._fails.pop(ip, None)
                self._locked_until.pop(ip, None)
                return record, 'ok'
            now = time.time()
            if len(self._fails) >= 10000 and ip not in self._fails:
                oldest = next(iter(self._fails))
                self._fails.pop(oldest, None)
                self._locked_until.pop(oldest, None)
            fails = [t for t in self._fails.get(ip, []) if now - t < self.window]
            fails.append(now)
            self._fails[ip] = fails
            if len(fails) >= self.max_attempts:
                self._locked_until[ip] = now + self.lockout
                self._fails[ip] = []
                return None, 'locked'
        return None, 'bad'

    def verify(self, username, password, ip='?'):
        record, reason = self._validate(username, password, ip)
        return bool(record), reason

    def login(self, username, password, ip, lifetime):
        record, reason = self._validate(username, password, ip)
        if not record:
            return None, reason
        if self.user_store:
            token = self.user_store.issue(record['username'], record['version'], lifetime)
        else:
            from modules.identity import token_hash
            token, now = secrets.token_urlsafe(32), time.time()
            with self._lock:
                self._sessions = {key:value for key,value in self._sessions.items() if value['expires'] > now}
                if len(self._sessions) >= 20:
                    self._sessions.pop(next(iter(self._sessions)))
                self._sessions[token_hash(token)] = {'username':self.username, 'role':'admin', 'version':1, 'expires':now+lifetime}
        return token, 'ok' if token else 'bad'

    def principal(self, token):
        if not token:
            return None
        if self.user_store:
            return self.user_store.principal(token)
        from modules.identity import token_hash
        with self._lock:
            record = self._sessions.get(token_hash(token))
            return dict(record) if record and record['expires'] > time.time() else None

    def revoke(self, token):
        if self.user_store:
            self.user_store.revoke(token)
        else:
            from modules.identity import token_hash
            with self._lock:
                self._sessions.pop(token_hash(token), None)
