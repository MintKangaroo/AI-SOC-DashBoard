"""전역 감사 로그 — 분석가 조치(알림 상태변경·차단·인시던트 갱신)를 append-only 로 기록.

SOC 책임추적성·근무 인수인계의 기본. 인시던트별 타임라인과 별개로
"누가 언제 무엇을 했는가"를 한 테이블에 모아 조회한다.
"""
import os
import sqlite3
import threading
from datetime import datetime

# 액션 코드 → 한글 (UI 표시·필터)
ACTIONS = {
    "ALERT_ACK":     "알림 확인(ACK)",
    "ALERT_CLOSE":   "알림 종료(CLOSED)",
    "ALERT_REOPEN":  "알림 재오픈",
    "SOAR_BLOCK":    "IP 수동 차단",
    "SOAR_UNBLOCK":  "IP 차단 해제",
    "INCIDENT_STATUS": "인시던트 상태변경",
    "INCIDENT_ASSIGN": "인시던트 담당지정",
    "INCIDENT_NOTE":   "인시던트 메모",
    "WATCHLIST_ADD":   "워치리스트 추가",
    "WATCHLIST_REMOVE":"워치리스트 삭제",
    "ALERT_ARCHIVE":   "알림 아카이브",
    "RETENTION_RUN":   "보존 정책 수동 실행",
    "VIRUSTOTAL_TEST": "VirusTotal 연결 테스트",
}


class AuditLog:
    def __init__(self, db_path="data/audit.db"):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._lock = threading.Lock()
        with self._lock:
            # 감사 기록은 조치 경로(알림 ACK·차단·인시던트 변경)에서 동기로 쓰인다.
            # WAL 이라야 /api/audit 의 긴 조회가 그 쓰기를 막지 않는다.
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS audit (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts      TEXT,
                    actor   TEXT,
                    action  TEXT,
                    target  TEXT,
                    detail  TEXT
                )
            """)
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)")
            self._conn.commit()

    def record(self, actor, action, target="", detail=""):
        """조치 1건 기록. 실패해도 조치 자체는 막지 않도록 예외를 삼킨다."""
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO audit (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     actor or "system", action, str(target), str(detail)))
                self._conn.commit()
        except Exception:
            pass

    def search(self, action=None, actor=None, text=None,
               date_from=None, date_to=None, limit=100, offset=0):
        where, params = [], []
        if action:
            where.append("action = ?"); params.append(action)
        if actor:
            where.append("actor LIKE ?"); params.append(f"%{actor}%")
        if text:
            where.append("(target LIKE ? OR detail LIKE ?)")
            params += [f"%{text}%", f"%{text}%"]
        if date_from:
            where.append("ts >= ?"); params.append(f"{date_from} 00:00:00")
        if date_to:
            where.append("ts <= ?"); params.append(f"{date_to} 23:59:59")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM audit {clause}", params).fetchone()[0]
            rows = self._conn.execute(
                f"""SELECT id, ts, actor, action, target, detail
                    FROM audit {clause} ORDER BY id DESC LIMIT ? OFFSET ?""",
                params + [int(limit), int(offset)]).fetchall()
        result = [{"id": r[0], "ts": r[1], "actor": r[2], "action": r[3],
                   "action_label": ACTIONS.get(r[3], r[3]),
                   "target": r[4], "detail": r[5]} for r in rows]
        return result, total

    def purge_older_than(self, days):
        """N일 이전 감사 로그 영구 삭제. 삭제 건수 반환."""
        try:
            with self._lock:
                cnt = self._conn.execute(
                    "SELECT COUNT(*) FROM audit WHERE ts < datetime('now', ?, 'localtime')",
                    (f"-{int(days)} days",)).fetchone()[0]
                self._conn.execute(
                    "DELETE FROM audit WHERE ts < datetime('now', ?, 'localtime')",
                    (f"-{int(days)} days",))
                self._conn.commit()
            return cnt
        except Exception:
            return 0

    def count_older_than(self, days):
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM audit WHERE ts < datetime('now', ?, 'localtime')",
                (f"-{int(days)} days",)).fetchone()[0]

    def labels(self):
        return dict(ACTIONS)

    def close(self):
        with self._lock:
            self._conn.close()
