"""인시던트 영속화 — 증분 저장 회귀 테스트 (docs/AUDIT.md B-1 / B-2).

이전 구현은 매 저장마다 `self.incidents` 전량을 재직렬화하고
`DELETE ... WHERE id NOT IN (?,?,…)` 로 재조정했다.

- B-1: 실측 23,299건 기준 저장 1회 0.63초. 그 동안 `self._lock` 을 잡아
  SOAR 정탐 승격 경로(`promote_alert`)를 막았다.
- B-2: `NOT IN` 바인드 변수가 인시던트 수만큼 늘어 SQLite 상한 32,766 에
  걸리면 저장이 실패하는데, 예외를 print 만 하므로 **영속화가 조용히 멈춘다.**

정확성이 성능보다 중요하므로 왕복 보존을 먼저 검증한다.
"""
import json
import sqlite3

import pytest

from modules.incidents import IncidentManager


class FakeSocketIO:
    def __init__(self):
        self.events = []

    def emit(self, event, data=None, **kwargs):
        self.events.append((event, data))


class SpyConnection:
    """sqlite3.Connection 위임 프록시.

    Connection 은 C 확장 타입이라 monkeypatch.setattr 로 메서드를 교체할 수 없다
    ('attribute is read-only'). 저장이 정말 변경분만 쓰는지 세려면 감싸야 한다.
    """

    def __init__(self, conn, fail_on_executemany=False):
        self._conn = conn
        self.executemany_batches = []      # 호출별 행 수
        self.fail_on_executemany = fail_on_executemany

    def executemany(self, sql, rows):
        rows = list(rows)
        self.executemany_batches.append(len(rows))
        if self.fail_on_executemany:
            raise sqlite3.OperationalError("디스크 오류")
        return self._conn.executemany(sql, rows)

    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, *exc):
        return self._conn.__exit__(*exc)

    def __getattr__(self, name):          # execute, commit, close ...
        return getattr(self._conn, name)


def _alert(aid=1, threat="BRUTE_FORCE", src="203.0.113.9", sev="HIGH"):
    return {"id": aid, "threat_type": threat, "severity": sev, "src_ip": src,
            "threat_label": "무차별 대입", "details": {}}


@pytest.fixture
def mgr(tmp_path):
    m = IncidentManager(FakeSocketIO(), store_path=str(tmp_path / "inc.db"),
                        save_debounce_seconds=0)
    yield m
    if getattr(m, "_db", None):
        m._db.close()


# ─────────── 정확성: 왕복 보존 ───────────

def test_promoted_incident_persists_across_reopen(tmp_path):
    path = str(tmp_path / "inc.db")
    m1 = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    inc_id = m1.promote_alert(_alert())
    m1._db.close()

    m2 = IncidentManager(FakeSocketIO(), store_path=path)
    try:
        assert inc_id in m2.incidents
        assert m2.incidents[inc_id]["threat_type"] == "BRUTE_FORCE"
        assert m2._next_id > inc_id
    finally:
        m2._db.close()


def test_update_persists_across_reopen(tmp_path):
    path = str(tmp_path / "inc.db")
    m1 = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    inc_id = m1.promote_alert(_alert())
    assert m1.update(inc_id, status="CONTAINED", assignee="분석가A", note="조치함")
    m1._db.close()

    m2 = IncidentManager(FakeSocketIO(), store_path=path)
    try:
        inc = m2.incidents[inc_id]
        assert inc["status"] == "CONTAINED"
        assert inc["assignee"] == "분석가A"
        assert any(t["kind"] == "note" for t in inc["timeline"])
    finally:
        m2._db.close()


def test_attach_block_persists(tmp_path):
    path = str(tmp_path / "inc.db")
    m1 = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    inc_id = m1.promote_alert(_alert(src="203.0.113.9"))
    m1.attach_block("203.0.113.9", "자동 차단")
    m1._save()
    m1._db.close()

    m2 = IncidentManager(FakeSocketIO(), store_path=path)
    try:
        inc = m2.incidents[inc_id]
        assert any(t["kind"] == "block" for t in inc["timeline"])
        assert inc["status"] == "INVESTIGATING"
    finally:
        m2._db.close()


def test_multiple_incidents_all_persist(tmp_path):
    path = str(tmp_path / "inc.db")
    m1 = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    ids = [m1.promote_alert(_alert(aid=i, threat=f"T{i}", src=f"203.0.113.{i}"))
           for i in range(1, 21)]
    m1._db.close()

    m2 = IncidentManager(FakeSocketIO(), store_path=path)
    try:
        assert set(ids) == set(m2.incidents.keys())
    finally:
        m2._db.close()


# ─────────── 증분 저장 (B-1) ───────────

def test_load_leaves_nothing_dirty(tmp_path):
    """방금 DB 에서 읽은 것을 다시 쓸 이유가 없다."""
    path = str(tmp_path / "inc.db")
    m1 = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    m1.promote_alert(_alert())
    m1._db.close()

    m2 = IncidentManager(FakeSocketIO(), store_path=path)
    try:
        assert m2._dirty == set()
        assert m2._meta_dirty is False
    finally:
        m2._db.close()


def test_save_writes_only_changed_rows(mgr):
    """전량 재작성이 되살아나면 이 테스트가 실패한다."""
    for i in range(1, 11):
        mgr.promote_alert(_alert(aid=i, threat=f"T{i}", src=f"203.0.113.{i}"))
    assert mgr._dirty == set()          # debounce=0 이라 즉시 저장됨

    spy = SpyConnection(mgr._db)
    mgr._db = spy
    mgr.update(3, status="CONTAINED")
    assert spy.executemany_batches == [1], (
        f"1건만 써야 하는데 {spy.executemany_batches} 건을 씀 "
        f"(전량 재작성이면 10)")


def test_no_write_when_nothing_changed(mgr):
    mgr.promote_alert(_alert())
    spy = SpyConnection(mgr._db)
    mgr._db = spy
    mgr._save_sqlite()
    assert spy.executemany_batches == [], "변경이 없는데 저장을 시도함"


def test_failed_save_keeps_dirty_for_retry(mgr):
    """저장 실패 시 dirty 를 비우면 그 변경분은 영영 유실된다."""
    inc_id = mgr.promote_alert(_alert())
    mgr.incidents[inc_id]["status"] = "CONTAINED"
    mgr._dirty.add(inc_id)

    real_conn = mgr._db
    mgr._db = SpyConnection(real_conn, fail_on_executemany=True)
    mgr._save_sqlite()
    assert inc_id in mgr._dirty, "실패했는데 dirty 를 비움 — 변경 유실"

    # 복구 후 재시도하면 살아남아야 한다
    mgr._db = real_conn
    mgr._save_sqlite()
    assert inc_id not in mgr._dirty
    row = mgr._db.execute("SELECT payload FROM incidents WHERE id=?",
                          (inc_id,)).fetchone()
    assert json.loads(row[0])["status"] == "CONTAINED"


# ─────────── SQLite 변수 상한 (B-2) ───────────

def test_no_variable_limit_on_large_incident_count(tmp_path):
    """이전 구현의 `NOT IN (?,?,…)` 는 32,766건에서 저장이 조용히 멈췄다.

    실제로 33,000건을 만들어 저장이 끝까지 성공하는지 확인한다.
    """
    path = str(tmp_path / "inc.db")
    m = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    try:
        # 상한(32,766)을 넘기는 규모를 직접 주입 — promote_alert 로 만들면 느리다
        for i in range(1, 33_001):
            m.incidents[i] = {"id": i, "title": f"inc{i}", "threat_type": "T",
                              "src_net": "203.0.113.0/24", "severity": "HIGH",
                              "status": "OPEN", "assignee": "", "alert_ids": [],
                              "created": "2026-08-27 00:00:00",
                              "updated": "2026-08-27 00:00:00", "timeline": []}
        m._next_id = 33_001
        m._mark_all_dirty()
        m._save_sqlite()

        assert m._dirty == set(), "33,000건 저장이 완료되지 않음"
        stored = m._db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        assert stored == 33_000, f"저장된 행이 부족: {stored}"

        # 이 규모에서 1건 갱신도 정상이어야 한다
        m.incidents[500]["status"] = "RESOLVED"
        m._dirty.add(500)
        m._save_sqlite()
        row = m._db.execute("SELECT payload FROM incidents WHERE id=500").fetchone()
        assert json.loads(row[0])["status"] == "RESOLVED"
    finally:
        m._db.close()


# ─────────── 이관 경로 ───────────

def test_json_migration_writes_everything(tmp_path):
    """JSON → SQLite 최초 이관은 전량 저장이어야 한다."""
    legacy = tmp_path / "inc.json"
    payload = {"next_id": 4, "incidents": {
        str(i): {"id": i, "title": f"레거시{i}", "threat_type": "T",
                 "src_net": "10.0.0.0/24", "severity": "HIGH", "status": "OPEN",
                 "assignee": "", "alert_ids": [], "created": "2026-01-01 00:00:00",
                 "updated": "2026-01-01 00:00:00", "timeline": []}
        for i in (1, 2, 3)}}
    legacy.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    m = IncidentManager(FakeSocketIO(), store_path=str(tmp_path / "inc.db"))
    try:
        assert len(m.incidents) == 3
        stored = m._db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        assert stored == 3, "이관이 전량 저장되지 않음"
        assert m._next_id == 4
    finally:
        m._db.close()


def test_stats_and_listing_still_work(mgr):
    for i in range(1, 6):
        mgr.promote_alert(_alert(aid=i, threat=f"T{i}", src=f"203.0.113.{i}"))
    stats = mgr.get_stats()
    assert stats["total"] == 5
    assert len(mgr.get_all(limit=3)) == 3
