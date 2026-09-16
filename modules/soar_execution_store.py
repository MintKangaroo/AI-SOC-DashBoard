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

# 프로세스가 죽으면 그 자리에서 멈춘 실행들. 다음 기동 때 **종료 상태로 정리**한다.
# waiting_approval 은 여기 없다 — 그건 사람의 결정을 기다리는 것이지 끊긴 게 아니다.
# 살아남을 프로세스가 없으므로 running/pending/processing_approval 은 전부 고아다.
INTERRUPTED_CANDIDATES = ("running", "pending", "processing_approval")


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

    def recover_interrupted(self):
        """이전 프로세스에서 끊긴 실행을 `interrupted` 로 닫는다. 반환: 건수.

        끊긴 실행은 **아무도 이어받지 않는다.** 그런데 `running` 은 정리 대상에서
        제외되는 상태라(NON_TERMINAL_STATUSES) 보존 루프도 건드리지 않아, 서버가
        한 번 죽을 때마다 화면과 통계에 영원히 '진행 중' 으로 남는다. 실제로
        2026-08-27~29 에 죽은 4건이 3주 가까이 그렇게 남아 있었다.

        `completed` 로 닫지 않는 이유는 **끝난 적이 없기 때문**이다. 상태 이름이
        사실과 달라지면 이후 통계가 전부 거짓이 된다. 진행 중이던 단계도 그대로
        `interrupted` 로 적어, 어디서 끊겼는지 나중에 볼 수 있게 남긴다.

        `finished` 는 **비워 둔다.** 정리한 시각을 적으면 그게 종료 시각인 양
        보이고, 보존 계산도 그 시점부터 다시 90일을 세어 기록이 그만큼 더 남는다.
        비워 두면 `_purge_clause` 가 `started` 로 판단한다 — 원래 비정상 종료를
        위해 만들어 둔 길이다.
        """
        marks = ",".join("?" for _ in INTERRUPTED_CANDIDATES)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT id, snapshot FROM executions WHERE status IN ({marks})",
                INTERRUPTED_CANDIDATES).fetchall()
            for run_id, snapshot in rows:
                try:
                    entry = json.loads(snapshot)
                except (TypeError, ValueError):
                    entry = {"id": run_id}
                entry["status"] = "interrupted"
                entry["current_step"] = None
                for step in entry.get("steps") or []:
                    if step.get("status") in ("running", "pending"):
                        step["status"] = "interrupted"
                        detail = (step.get("detail") or "").strip()
                        step["detail"] = (detail + " · " if detail else "") + "서버가 멈춰 여기서 끊김"
                self._conn.execute(
                    "UPDATE executions SET status=?, snapshot=? WHERE id=?",
                    ("interrupted", json.dumps(entry, ensure_ascii=False), run_id))
            if rows:
                self._conn.commit()
        return len(rows)

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
