"""Local identity directory and revocable sessions. Never exports credential hashes."""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager

from werkzeug.security import generate_password_hash

ROLES = {
    'viewer': frozenset({'read', 'profile'}),
    'analyst': frozenset({'read', 'profile', 'investigate'}),
    'responder': frozenset({'read', 'profile', 'investigate', 'respond', 'scan'}),
    'admin': frozenset({'read', 'profile', 'investigate', 'respond', 'scan', 'tune', 'admin'}),
}


def validate_username(username):
    if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}', username):
        raise ValueError('Username must be 3–64 ASCII letters, digits, dot, @, underscore or hyphen.')


def password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError('Use a password of 12–256 characters.')
    return generate_password_hash(password)


def token_hash(token):
    return hashlib.sha256(str(token or '').encode()).hexdigest()


class IdentityStore:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # New credential files are private from creation, not chmod-ed after first write.
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute('PRAGMA journal_mode=WAL')
            self._conn.execute('PRAGMA foreign_keys=ON')
            self._conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('viewer','analyst','responder','admin')),
                    active INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 1,
                    created REAL NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username),
                    version INTEGER NOT NULL, issued REAL NOT NULL, expires REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS session_user ON sessions(username);
                CREATE TABLE IF NOT EXISTS identity_audit (
                    id INTEGER PRIMARY KEY, ts REAL NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL);
            ''')

    @contextmanager
    def _write(self, actor, require_admin=True):
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                if isinstance(actor, dict):
                    current = self._conn.execute('SELECT role, active, version FROM users WHERE username=?', (actor['username'],)).fetchone()
                    if not current or not current['active'] or (require_admin and current['role'] != 'admin') or current['version'] != actor['version']:
                        raise PermissionError('관리자 세션이 바뀌었습니다. 다시 로그인하세요.')
                yield
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _audit(self, actor, action, target, detail):
        self._conn.execute('INSERT INTO identity_audit(ts,actor,action,target,detail) VALUES(?,?,?,?,?)',
                           (time.time(), actor['username'] if isinstance(actor, dict) else actor,
                            action, target, json.dumps(detail, ensure_ascii=False)))

    def bootstrap(self, username, encoded):
        """One-time explicit managed-mode bootstrap. Never overwrites an existing directory."""
        if not encoded:
            return
        validate_username(username)
        with self._write('bootstrap'):
            if self._conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
                now = time.time()
                self._conn.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)', (username, encoded, 'admin', 1, 1, now, now))
                self._audit('bootstrap', 'USER_BOOTSTRAP', username, {'role':'admin'})

    def create(self, username, password, role, *, actor, reason):
        validate_username(username)
        if not isinstance(role, str) or role not in ROLES:
            raise ValueError('Unknown role.')
        encoded = password_hash(password)
        with self._write(actor):
            if self._conn.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                raise ValueError('Username already exists.')
            if self._conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0 and role != 'admin':
                raise ValueError('The first managed user must be an administrator.')
            now = time.time()
            self._conn.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)', (username, encoded, role, 1, 1, now, now))
            self._audit(actor, 'USER_CREATE', username, {'role':role, 'reason':reason})
        return self.get(username)

    def change(self, username, *, actor, reason, role=None, active=None, password=None, revoke=False):
        if role is not None and (not isinstance(role, str) or role not in ROLES):
            raise ValueError('Unknown role.')
        if active is not None and type(active) is not bool:
            raise ValueError('Active must be a boolean.')
        encoded = password_hash(password) if password is not None else None
        with self._write(actor):
            old = self._conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            if old is None:
                raise ValueError('User not found.')
            new_role, new_active = role if role is not None else old['role'], int(active if active is not None else old['active'])
            if isinstance(actor, dict) and actor['username'] == username and (new_role != old['role'] or not new_active):
                raise ValueError('An administrator cannot demote or disable their own account.')
            if old['role'] == 'admin' and old['active'] and (new_role != 'admin' or not new_active):
                count = self._conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
                if count <= 1:
                    raise ValueError('Keep at least one active administrator.')
            self._conn.execute('UPDATE users SET role=?,active=?,password_hash=?,version=version+1,updated=? WHERE username=?',
                               (new_role, new_active, encoded or old['password_hash'], time.time(), username))
            self._conn.execute('DELETE FROM sessions WHERE username=?', (username,))
            self._audit(actor, 'USER_CHANGE', username, {'from_role':old['role'], 'role':new_role,
                        'active':bool(new_active), 'password_changed':encoded is not None,
                        'sessions_revoked':True, 'reason':reason, 'revoke_requested':revoke})
        return self.get(username)

    def change_password(self, actor, password):
        encoded = password_hash(password)
        with self._write(actor, require_admin=False):
            self._conn.execute('UPDATE users SET password_hash=?,version=version+1,updated=? WHERE username=?',
                               (encoded,time.time(),actor['username']))
            self._conn.execute('DELETE FROM sessions WHERE username=?', (actor['username'],))
            self._audit(actor, 'PASSWORD_CHANGE', actor['username'], {'sessions_revoked':True})

    def credentials(self, username):
        """Internal only. Callers must never serialize this result."""
        with self._lock:
            row = self._conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        return dict(row) if row else None

    def get(self, username):
        record = self.credentials(username)
        return {k:record[k] for k in ('username','role','active','version','created','updated')} if record else None

    def list_users(self):
        with self._lock:
            rows = self._conn.execute('SELECT username,role,active,version,created,updated FROM users ORDER BY username').fetchall()
        return [dict(row) for row in rows]

    def issue(self, username, version, lifetime):
        token, now = secrets.token_urlsafe(32), time.time()
        with self._write('session'):
            record = self._conn.execute('SELECT active,version FROM users WHERE username=?', (username,)).fetchone()
            if not record or not record['active'] or record['version'] != version:
                return None
            self._conn.execute('DELETE FROM sessions WHERE expires<=?', (now,))
            # Bound active sessions per account; oldest sessions are revoked first.
            self._conn.execute('DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE username=? ORDER BY issued DESC LIMIT -1 OFFSET 19)', (username,))
            self._conn.execute('INSERT INTO sessions VALUES(?,?,?,?,?)', (token_hash(token),username,version,now,now+lifetime))
        return token

    def principal(self, token):
        with self._lock:
            row = self._conn.execute('''SELECT u.username,u.role,u.version,s.expires FROM sessions s JOIN users u
                ON u.username=s.username WHERE s.token_hash=? AND u.active=1 AND u.version=s.version AND s.expires>?''',
                (token_hash(token),time.time())).fetchone()
        return dict(row) if row else None

    def revoke(self, token):
        with self._write('session'):
            self._conn.execute('DELETE FROM sessions WHERE token_hash=?', (token_hash(token),))

    def audit(self, limit=100):
        with self._lock:
            rows = self._conn.execute('SELECT * FROM identity_audit ORDER BY id DESC LIMIT ?', (min(200,max(1,limit)),)).fetchall()
        return [dict(row) for row in rows]

    def close(self):
        self._conn.close()
