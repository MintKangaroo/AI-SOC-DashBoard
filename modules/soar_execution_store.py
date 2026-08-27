"""SOAR 플레이북 실행 이력을 보존하는 SQLite 저장소."""
import json
import os
import sqlite3
import threading

# 정리 대상에서 **항상 제외**하는 상태.
# 제외 목록으로 정의하는 이유: 새 상태값이 생겨도 기본이 '보존'이 되게 하기 위함이다.
# 특히 waiting_approval 은 사람의 결정을 기다리는 항목이라 지우면 그 결정 기회가
# 사라진다(실 DB 기준 1,685건). processing_approval/running/pending 도 진행 중이다.
NON_TERMINAL_STATUSES = ("waiting_approval", "processing_approval", "running", "pending")


class SOARExecutionStore:
    def __init__(self, db_path="data/soar_executions.db"):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY,
                    playbook TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started TEXT NOT NULL,
                    finished TEXT,
                    snapshot TEXT NOT NULL,
                    context TEXT NOT NULL DEFAULT '{}'
                )
            """)
            self._conn.commit()

    def save(self, entry, context=None):
        """스냅샷을 upsert한다. context=None이면 기존 재시도 컨텍스트를 보존한다."""
        snapshot = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            if context is None:
                self._conn.execute(
                    """INSERT INTO executions(id, playbook, status, started, finished, snapshot)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET playbook=excluded.playbook,
                         status=excluded.status, started=excluded.started,
                         finished=excluded.finished, snapshot=excluded.snapshot""",
                    (entry["id"], entry["playbook"], entry["status"], entry["started"],
                     entry.get("finished"), snapshot),
                )
            else:
                self._conn.execute(
                    """INSERT INTO executions
                       (id, playbook, status, started, finished, snapshot, context)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET playbook=excluded.playbook,
                         status=excluded.status, started=excluded.started,
                         finished=excluded.finished, snapshot=excluded.snapshot,
                         context=excluded.context""",
                    (entry["id"], entry["playbook"], entry["status"], entry["started"],
                     entry.get("finished"), snapshot,
                     json.dumps(context, ensure_ascii=False)),
                )
            self._conn.commit()

    def counts_by_status(self):
        with self._lock:
            return dict(self._conn.execute(
                "SELECT status, COUNT(*) FROM executions GROUP BY status").fetchall())

    def _purge_clause(self):
        """정리 대상 조건 — 종료 상태이면서 기준 시각이 지난 것."""
        marks = ",".join("?" for _ in NON_TERMINAL_STATUSES)
        # finished 가 없으면 started 로 판단한다(비정상 종료 등)
        return (f"status NOT IN ({marks}) "
                "AND COALESCE(NULLIF(finished,''), started) < datetime('now', ?, 'localtime')")

    def count_purgeable(self, days):
        with self._lock:
            return self._conn.execute(
                f"SELECT COUNT(*) FROM executions WHERE {self._purge_clause()}",
                (*NON_TERMINAL_STATUSES, f"-{int(days)} days")).fetchone()[0]

    def purge_terminal_older_than(self, days):
        """종료된 실행 이력만 정리한다. 승인 대기·진행 중은 건드리지 않는다.

        반환: 삭제 건수.
        """
        params = (*NON_TERMINAL_STATUSES, f"-{int(days)} days")
        with self._lock:
            n = self._conn.execute(
                f"SELECT COUNT(*) FROM executions WHERE {self._purge_clause()}",
                params).fetchone()[0]
            if n:
                self._conn.execute(
                    f"DELETE FROM executions WHERE {self._purge_clause()}", params)
                self._conn.commit()
        return n

    def load_recent(self, limit=100):
        with self._lock:
            rows = self._conn.execute(
                "SELECT snapshot FROM executions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        result = []
        for row in rows:
            try:
                result.append(json.loads(row[0]))
            except (TypeError, json.JSONDecodeError):
                continue
        return result

    def get(self, execution_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT snapshot, context FROM executions WHERE id=?", (execution_id,)
            ).fetchone()
        if not row:
            return None, None
        try:
            return json.loads(row[0]), json.loads(row[1] or "{}")
        except (TypeError, json.JSONDecodeError):
            return None, None
