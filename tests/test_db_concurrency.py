"""SQLite 동시성 — WAL·busy_timeout (docs/AUDIT.md B-7 / #21).

`incidents`·`alert_dedup`·`soar_executions`·`ml_features` 는 WAL 을 쓰는데
`alerts`·`audit`·`watchlist` 는 기본 rollback journal 이었다. 이 셋은 모두
탐지·조치 경로에서 동기로 쓰이면서 동시에 긴 조회(이력 검색 11만 행, 감사
로그 페이지네이션)의 대상이라, 읽기가 쓰기를 막는 구조였다.

`alert_store` 는 아카이브 DB 를 ATTACH 한다. WAL 에서 SQLite 는 여러 DB 에
걸친 커밋의 원자성을 보장하지 않으므로, 복사와 삭제를 한 트랜잭션에 두면
크래시 시 **삭제만 반영되어 알림이 유실될 수 있다.** 그래서 이동을 2단계로
쪼갰고, 이 파일이 지키는 불변식은 그것이다: **최악의 경우가 중복이어야지
유실이어서는 안 된다.**
"""
import sqlite3

import pytest

from modules.alert_store import AlertStore
from modules.audit_log import AuditLog
from modules.threat_detector import Alert
from modules.watchlist import Watchlist


def _alert(ts, src="1.2.3.4", desc="x"):
    a = Alert("DDOS", "HIGH", src, "5.6.7.8", desc)
    a.timestamp = ts
    return a


# ─────────────────────── WAL 활성 확인 ───────────────────────

def test_all_hot_stores_use_wal(tmp_path):
    """탐지·조치 경로에서 쓰이는 저장소는 전부 WAL 이어야 한다."""
    stores = {
        "alerts": AlertStore(str(tmp_path / "a.db")),
        "audit": AuditLog(str(tmp_path / "u.db")),
        "watchlist": Watchlist(db_path=str(tmp_path / "w.db")),
    }
    try:
        for name, st in stores.items():
            conn = st._conn
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal", name
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10000, name
    finally:
        for st in stores.values():
            st.close()


def test_alert_store_enables_wal_on_attached_archive(tmp_path):
    """WAL 은 DB 단위 설정 — ATTACH 된 아카이브에도 걸려 있어야 한다."""
    store = AlertStore(str(tmp_path / "a.db"))
    try:
        assert store._conn.execute("PRAGMA archive.journal_mode").fetchone()[0] == "wal"
    finally:
        store.close()


def test_long_read_does_not_block_write(tmp_path):
    """긴 조회가 열려 있어도 다른 커넥션이 알림을 쓸 수 있다 (WAL 의 목적)."""
    path = str(tmp_path / "a.db")
    store = AlertStore(path)
    try:
        store.save(_alert("2026-01-01 00:00:00"))
        # 별도 커넥션에서 읽기 트랜잭션을 연 채로 유지한다.
        reader = sqlite3.connect(path, timeout=1)
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM alerts").fetchone()
        try:
            store.save(_alert("2026-01-02 00:00:00"))   # 잠기면 여기서 실패
            assert store.search(scope="live")[1] == 2
        finally:
            reader.close()
    finally:
        store.close()


# ─────────── 아카이브 이동: 유실보다 중복 (2단계 커밋) ───────────

def test_archive_move_survives_crash_between_phases(tmp_path):
    """복사 커밋 직후 죽어도 알림은 남고, 재기동이 이동을 마저 끝낸다."""
    path = str(tmp_path / "a.db")
    store = AlertStore(path)
    store.save(_alert("2020-01-01 00:00:00", src="9.9.9.9", desc="오래된 알림"))
    store.save(_alert("2020-01-01 00:00:01", src="9.9.9.9", desc="오래된 알림2"))

    # 1단계(복사)만 수행하고 2단계(삭제) 전에 프로세스가 죽은 상황을 만든다.
    with store._lock:
        store._ensure_archive()
        store._conn.execute(
            """INSERT OR REPLACE INTO archive.alerts_archive
               (id, threat_type, severity, src_ip, dst_ip, description, details,
                timestamp, status, note, assignee, archived_at, origin, verdict,
                verdict_actor, verdict_reason, verdict_at)
               SELECT id, threat_type, severity, src_ip, dst_ip, description, details,
                      timestamp, status, note, assignee, '2026-01-01 00:00:00', origin,
                      verdict, verdict_actor, verdict_reason, verdict_at
               FROM alerts""")
        store._conn.commit()
    store._conn.close()          # 크래시 — 삭제는 커밋되지 않았다

    # 재기동: 양쪽에 남은 사본을 정리해 이동을 완료한다. 유실은 없다.
    store = AlertStore(path)
    try:
        assert store.recovered_duplicates == 2
        stats = store.retention_stats()
        assert stats["live"] == 0 and stats["archived"] == 2
        rows, total = store.search()
        assert total == 2                              # ← 핵심: 한 건도 안 사라졌다
        assert all(r["archived"] for r in rows)
        assert {r["description"] for r in rows} == {"오래된 알림", "오래된 알림2"}
    finally:
        store.close()


def test_recovery_keeps_live_alert_that_only_shares_id(tmp_path):
    """id 만 같고 내용이 다른 활성 알림은 이동 잔재가 아니므로 지우지 않는다."""
    path = str(tmp_path / "a.db")
    store = AlertStore(path)
    store.save(_alert("2020-01-01 00:00:00", desc="아카이브로 간 것"))
    assert store.archive_older_than(1) == 1

    live = _alert("2026-06-01 12:00:00", desc="같은 id 를 쓰는 새 알림")
    live.id = store.search(scope="archive")[0][0]["id"]
    store.save(live)
    store._conn.close()

    store = AlertStore(path)
    try:
        assert store.recovered_duplicates == 0
        assert store.retention_stats()["live"] == 1
        assert store.search(scope="live")[0][0]["description"] == "같은 id 를 쓰는 새 알림"
    finally:
        store.close()


@pytest.mark.parametrize("mover", ["archive_older_than", "production_cutover"])
def test_archive_moves_are_lossless(tmp_path, mover):
    """두 이동 경로 모두 무손실이며 통합 조회에서 계속 보인다."""
    store = AlertStore(str(tmp_path / f"{mover}.db"))
    try:
        for i in range(5):
            store.save(_alert(f"2020-01-01 00:00:0{i}", desc=f"알림{i}"))
        if mover == "archive_older_than":
            assert store.archive_older_than(1) == 5
        else:
            assert store.production_cutover("2026-01-01 00:00:00") == 5
        assert store.retention_stats() == {**store.retention_stats(),
                                           "live": 0, "archived": 5}
        rows, total = store.search()
        assert total == 5
        assert {r["description"] for r in rows} == {f"알림{i}" for i in range(5)}
    finally:
        store.close()


class _RecordingConn:
    """실행되는 SQL 과 commit 을 순서대로 기록하는 얇은 프록시."""

    def __init__(self, conn, log):
        self._conn, self._log = conn, log

    def execute(self, sql, *a, **k):
        head = " ".join(sql.split())[:40]
        if head.startswith(("INSERT", "DELETE", "UPDATE")):
            self._log.append(head)
        return self._conn.execute(sql, *a, **k)

    def commit(self):
        self._log.append("COMMIT")
        return self._conn.commit()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_archive_copy_is_committed_before_delete(tmp_path):
    """복사와 삭제 사이에 커밋이 있어야 한다.

    한 트랜잭션에 묶으면 WAL + ATTACH 조합에서 삭제만 반영될 수 있고, 그것이
    곧 알림 유실이다. 크래시는 인프로세스로 재현할 수 없으므로 순서를 직접
    검증한다.
    """
    store = AlertStore(str(tmp_path / "order.db"))
    try:
        store.save(_alert("2020-01-01 00:00:00"))
        log = []
        store._conn = _RecordingConn(store._conn, log)
        assert store.archive_older_than(1) == 1

        insert_at = next(i for i, e in enumerate(log) if e.startswith("INSERT"))
        delete_at = next(i for i, e in enumerate(log) if e.startswith("DELETE"))
        assert insert_at < delete_at
        assert "COMMIT" in log[insert_at + 1:delete_at], (
            f"복사와 삭제 사이에 커밋이 없다: {log}")
    finally:
        store._conn = store._conn._conn
        store.close()


# ──────────── 읽기/쓰기 커넥션 분리 (AUDIT B-7 후반부) ────────────

def test_reader_connection_cannot_write(tmp_path):
    """조회 커넥션은 query_only — 실수로도 쓰기가 나가지 않는다."""
    store = AlertStore(str(tmp_path / "ro.db"))
    try:
        with pytest.raises(sqlite3.OperationalError):
            store._read_conn.execute("DELETE FROM alerts")
    finally:
        store.close()


def test_reads_do_not_take_the_write_lock(tmp_path):
    """조회가 쓰기 락을 잡지 않아야 탐지 경로가 지표 조회에 막히지 않는다.

    쓰기 락을 잡아둔 채로 조회를 호출한다. 조회가 같은 락을 쓰면 여기서
    영원히 멈춘다 — 그것이 WAL 을 켜기 전의 실제 동작이었다.
    """
    import threading

    store = AlertStore(str(tmp_path / "split.db"))
    try:
        store.save(_alert("2026-01-01 00:00:00"))
        done, error = threading.Event(), []

        def reader():
            try:
                for call in (lambda: store.search(limit=5),
                             lambda: store.aggregate(days=7),
                             lambda: store.since(hours=24),
                             lambda: store.grouped_recent(hours=24),
                             lambda: store.snort_sid_stats()):
                    call()
            except Exception as exc:      # pragma: no cover - 실패 시 진단용
                error.append(exc)
            finally:
                done.set()

        with store._lock:                 # 쓰기 락 점유 상태
            threading.Thread(target=reader, daemon=True).start()
            assert done.wait(timeout=5), "조회가 쓰기 락에 막혔다"
        assert not error, error
    finally:
        store.close()


def test_archive_move_blocks_readers_so_no_duplicate_is_visible(tmp_path):
    """이동 중에는 조회를 세운다 — 두 커밋 사이의 중복이 노출되면 안 된다."""
    import threading

    store = AlertStore(str(tmp_path / "movelock.db"))
    try:
        store.save(_alert("2020-01-01 00:00:00"))
        with store._read_lock:            # 조회가 진행 중인 상황
            started = threading.Event()
            finished = threading.Event()

            def mover():
                started.set()
                store.archive_older_than(1)
                finished.set()

            threading.Thread(target=mover, daemon=True).start()
            assert started.wait(timeout=5)
            # 읽기 락을 쥐고 있는 동안 이동은 완료될 수 없다
            assert not finished.wait(timeout=0.5)
        assert finished.wait(timeout=5)   # 놓아주면 끝난다
        assert store.search()[1] == 1
    finally:
        store.close()
