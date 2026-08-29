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
import time

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
            store._reader().execute("DELETE FROM alerts")
    finally:
        store.close()


def test_each_thread_gets_its_own_reader(tmp_path):
    """조회 커넥션 하나를 락으로 공유하면 WAL 의 동시 읽기가 무의미해진다.

    실측(11만 건): 단독 62ms 이던 `search(50)` 이 `aggregate` 와 겹치면
    최대 4,088ms — **66배**. 실서버 부하 시험에서 드러난 값이다.
    """
    import threading

    store = AlertStore(str(tmp_path / "pool.db"))
    try:
        seen = {}

        def grab(tag):
            seen[tag] = id(store._reader())

        threads = [threading.Thread(target=grab, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(seen.values())) == 3, "스레드가 커넥션을 공유하고 있다"
        assert id(store._reader()) not in seen.values()   # 메인 스레드도 자기 것
    finally:
        store.close()


def test_reads_do_not_block_each_other(tmp_path):
    """조회끼리 직렬화되면 무거운 집계 하나가 대시보드 전체를 세운다."""
    import threading
    import time

    store = AlertStore(str(tmp_path / "concurrent.db"))
    try:
        for i in range(200):
            store.save(_alert(f"2026-01-01 00:00:{i % 60:02d}", desc=f"a{i}"))

        holding = threading.Event()
        release = threading.Event()

        def slow_reader():
            conn = store._reader()
            conn.execute("BEGIN")
            conn.execute("SELECT COUNT(*) FROM alerts_all").fetchone()
            holding.set()
            release.wait(timeout=5)
            conn.execute("COMMIT")

        thread = threading.Thread(target=slow_reader, daemon=True)
        thread.start()
        assert holding.wait(timeout=5)
        start = time.time()
        store.search(limit=10)          # 다른 조회가 열려 있어도 즉시 끝나야 한다
        elapsed = time.time() - start
        release.set()
        thread.join(timeout=5)
        assert elapsed < 2.0, f"다른 조회에 막혔다: {elapsed:.1f}초"
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


def test_archive_move_is_not_visible_as_loss(tmp_path):
    """이동 중에 조회해도 알림이 사라져 보이면 안 된다.

    조회 커넥션이 스레드마다 따로라 이동을 락으로 막지는 않는다. 대신 복사를
    먼저 커밋하므로 최악이 '중복'이고 유실이 아니다 — 조회자가 무엇을 보든
    건수가 줄어드는 순간은 없다.
    """
    import threading

    store = AlertStore(str(tmp_path / "movelock.db"))
    try:
        for i in range(5):
            store.save(_alert(f"2020-01-01 00:00:0{i}", desc=f"old{i}"))
        seen = []
        stop = threading.Event()

        def watcher():
            while not stop.is_set():
                seen.append(store.search()[1])

        thread = threading.Thread(target=watcher, daemon=True)
        thread.start()
        store.archive_older_than(1)
        stop.set()
        thread.join(timeout=5)
        assert seen, "관찰된 값이 없다"
        assert min(seen) >= 5, f"이동 중에 알림이 사라져 보였다: {min(seen)}"
        assert store.search()[1] == 5
    finally:
        store.close()


# ─────────────── 집계 캐시 (실서버 부하 시험에서 나온 것) ───────────────

def test_aggregate_is_cached_but_staleness_is_visible(tmp_path):
    """집계 6개가 같은 행 집합을 각각 훑는다 — 폴링마다 치를 비용이 아니다.

    다만 **캐시가 staleness 를 숨기면 안 된다.** 화면이 얼마나 오래된 값을
    보고 있는지 알 수 있어야 한다.
    """
    store = AlertStore(str(tmp_path / "agg.db"))
    try:
        store.save(_alert("2026-01-01 00:00:00"))
        first = store.aggregate(days=3650)
        assert first["age_seconds"] == 0.0 and first["cached_at"]

        store.save(_alert("2026-01-02 00:00:00"))
        cached = store.aggregate(days=3650)
        assert cached["total"] == first["total"], "캐시가 안 먹었다"
        assert cached["age_seconds"] >= 0.0

        fresh = store.aggregate(days=3650, max_age=0)
        assert fresh["total"] == first["total"] + 1, "강제 재계산이 안 된다"
    finally:
        store.close()


def test_aggregate_cache_is_per_window(tmp_path):
    """기간이 다르면 다른 질문이다 — 한 캐시에 뭉뚱그리면 틀린 답이 나온다."""
    store = AlertStore(str(tmp_path / "agg2.db"))
    try:
        from datetime import datetime, timedelta
        recent = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        old = (datetime.now() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S")
        store.save(_alert(recent))
        store.save(_alert(old, src="9.9.9.9"))
        assert store.aggregate(days=7)["total"] == 1
        assert store.aggregate(days=365)["total"] == 2
    finally:
        store.close()


def test_aggregate_cache_can_be_disabled(tmp_path):
    store = AlertStore(str(tmp_path / "agg3.db"))
    try:
        store.aggregate_ttl = 0
        store.save(_alert("2026-01-01 00:00:00"))
        store.aggregate(days=3650)
        store.save(_alert("2026-01-02 00:00:00"))
        assert store.aggregate(days=3650)["total"] == 2, "TTL 0 인데 캐시가 먹었다"
    finally:
        store.close()


def test_concurrent_aggregates_compute_only_once(tmp_path):
    """같은 창을 동시에 물으면 한 번만 계산한다.

    실서버 부하 시험에서 동시 4요청이 전부 캐시 미스로 같은 1초짜리 집계를
    4번 돌렸다(thundering herd). 캐시만으로는 순차 폴링밖에 못 막는다.
    """
    import threading

    store = AlertStore(str(tmp_path / "herd.db"))
    try:
        store.save(_alert("2026-01-01 00:00:00"))
        calls = []
        original = store._aggregate_uncached

        def counted(*args, **kwargs):
            calls.append(1)
            time.sleep(0.2)          # 계산이 겹칠 시간을 준다
            return original(*args, **kwargs)

        store._aggregate_uncached = counted
        results = []
        threads = [threading.Thread(target=lambda: results.append(store.aggregate(days=3650)))
                   for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert len(calls) == 1, f"같은 집계를 {len(calls)}번 계산했다"
        assert len(results) == 5
        assert len({r["total"] for r in results}) == 1, "요청마다 다른 답을 줬다"
    finally:
        store.close()


def test_aggregate_failure_does_not_wedge_other_waiters(tmp_path):
    """선행 계산이 실패해도 기다리던 요청이 빈손으로 끝나면 안 된다."""
    import threading

    store = AlertStore(str(tmp_path / "herd2.db"))
    try:
        store.save(_alert("2026-01-01 00:00:00"))
        original = store._aggregate_uncached
        state = {"first": True}

        def flaky(*args, **kwargs):
            if state["first"]:
                state["first"] = False
                time.sleep(0.2)
                raise RuntimeError("첫 계산 실패")
            return original(*args, **kwargs)

        store._aggregate_uncached = flaky
        results, errors = [], []

        def call():
            try:
                results.append(store.aggregate(days=3650))
            except RuntimeError as e:
                errors.append(e)

        threads = [threading.Thread(target=call) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert len(errors) == 1, "실패는 호출자에게 보고돼야 한다"
        assert len(results) == 1, "기다리던 쪽이 결과를 못 받았다"
    finally:
        store.close()
