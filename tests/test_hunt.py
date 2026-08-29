"""위협 헌팅 콘솔 (docs/AUDIT.md 3단계 제안 #7).

`alert_store.search()` 는 이미 8개 조건을 지원했지만 **분석가가 매번 조건을 다시
입력해야 했다.** 헌팅은 반복 행위다 — "지난주에 봤던 그 패턴을 다시 본다"가
핵심인데 그 '그 패턴'을 어디에도 적어둘 수 없었다.

감사는 이 기능에 선행 조건을 달았다: `search()` 가 아카이브를 못 보면 헌팅
콘솔은 **껍데기**라는 것. 그래서 이 테스트가 가장 먼저 지키는 것은
**기본 검색 범위가 전체 이력이라는 사실**이다.

나머지 두 불변식:
- **델타가 정확할 것.** 매번 같은 결과를 다시 보여주면 사람은 곧 안 본다.
- **결과가 행동으로 이어질 것.** 워치리스트 승격이 없으면 그냥 조회다.
"""
import pytest

from modules.hunt import ALLOWED_FILTERS, STARTER_HUNTS, HuntStore


class _FakeStore:
    """search() 호출을 기록하는 알림 저장소 대역."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.calls = []

    def search(self, **filters):
        self.calls.append(filters)
        limit = filters.get("limit", 100)
        return list(self.rows)[:limit], len(self.rows)


class _FakeWatchlist:
    def __init__(self, fail=False):
        self.added = []
        self.fail = fail

    def add(self, ioc_type, value, note="", added_by="system"):
        if self.fail:
            raise RuntimeError("워치리스트 고장")
        self.added.append((ioc_type, value, note, added_by))
        return True


def _alerts(n, start_id=1, src="203.0.113.5"):
    return [{"id": start_id + i, "timestamp": f"2026-08-2{i % 9} 10:00:00",
             "severity": "CRITICAL", "threat_type": "WEB_ATTACK",
             "src_ip": src, "dst_ip": "10.0.0.1", "description": f"공격 {i}"}
            for i in range(n)]


@pytest.fixture
def hunts(tmp_path):
    store = HuntStore(db_path=str(tmp_path / "hunts.db"),
                      alert_store=_FakeStore(_alerts(5)),
                      watchlist=_FakeWatchlist())
    yield store
    store.close()


# ─────────────── 선행 조건: 전체 이력 위에서 사냥한다 ───────────────

def test_default_scope_is_full_history(hunts):
    """아카이브를 빼면 헌팅 콘솔은 껍데기다 — 감사가 단 선행 조건이다."""
    created = hunts.create("전체 이력", {"severity": "CRITICAL"})
    assert created["filters"]["scope"] == "all"
    hunts.run(created["id"])
    assert hunts.alert_store.calls[0]["scope"] == "all"


def test_explicit_scope_is_respected(hunts):
    created = hunts.create("활성만", {"severity": "HIGH", "scope": "live"})
    assert created["filters"]["scope"] == "live"


# ─────────────── 필터 위생 ───────────────

def test_unknown_filter_keys_are_dropped(hunts):
    """search() 가 모르는 키를 넘기면 TypeError 이거나 더 나쁘게는 오작동한다."""
    created = hunts.create("이상한 조건",
                           {"severity": "HIGH", "limit": 99999, "__proto__": "x",
                            "drop_table": "alerts"})
    assert set(created["filters"]) == {"severity", "scope"}
    assert set(created["dropped"]) == {"limit", "__proto__", "drop_table"}


def test_allowed_filters_match_search_signature():
    """허용 목록이 search() 의 실제 인자와 어긋나면 조용히 무시되거나 터진다."""
    import inspect

    from modules.alert_store import AlertStore
    params = set(inspect.signature(AlertStore.search).parameters) - {"self", "limit", "offset"}
    assert ALLOWED_FILTERS <= params, f"search() 에 없는 필터: {ALLOWED_FILTERS - params}"


def test_empty_filters_are_rejected(hunts):
    """조건 없는 헌팅은 '전부 보기'라 헌팅이 아니다."""
    with pytest.raises(ValueError):
        hunts.create("빈 조건", {})
    with pytest.raises(ValueError):
        hunts.create("공백만", {"severity": "", "ip": None})


def test_duplicate_name_is_rejected(hunts):
    hunts.create("중복", {"severity": "HIGH"})
    with pytest.raises(ValueError):
        hunts.create("중복", {"severity": "LOW"})


def test_unnamed_hunt_is_rejected(hunts):
    with pytest.raises(ValueError):
        hunts.create("   ", {"severity": "HIGH"})


# ─────────────── 델타: 지난번 이후 새로 걸린 것 ───────────────

def test_first_run_is_marked_as_baseline(hunts):
    """첫 실행은 전부가 '새것'이라 델타가 의미 없다 — 그걸 숨기지 않는다."""
    created = hunts.create("첫 실행", {"severity": "CRITICAL"})
    result = hunts.run(created["id"])
    assert result["first_run"] is True
    assert result["new_count"] == 5


def test_second_run_reports_no_new_matches(hunts):
    created = hunts.create("델타", {"severity": "CRITICAL"})
    hunts.run(created["id"])
    again = hunts.run(created["id"])
    assert again["first_run"] is False
    assert again["new_count"] == 0, "같은 결과를 또 '새것'이라 하면 사람이 안 본다"


def test_new_alerts_since_last_run_are_counted(hunts):
    created = hunts.create("델타2", {"severity": "CRITICAL"})
    hunts.run(created["id"])
    hunts.alert_store.rows = _alerts(3, start_id=100) + hunts.alert_store.rows
    result = hunts.run(created["id"])
    assert result["new_count"] == 3
    assert set(result["new_ids"]) == {100, 101, 102}


def test_preview_run_does_not_consume_the_delta(hunts):
    """미리보기로 돌려봤다고 '새로 걸린 것'이 사라지면 안 된다."""
    created = hunts.create("미리보기", {"severity": "CRITICAL"})
    hunts.run(created["id"], mark=False)
    assert hunts.get(created["id"])["run_count"] == 0
    real = hunts.run(created["id"])
    assert real["first_run"] is True and real["new_count"] == 5


def test_run_stats_are_recorded(hunts):
    created = hunts.create("통계", {"severity": "CRITICAL"})
    hunts.run(created["id"])
    hunts.run(created["id"])
    saved = hunts.get(created["id"])
    assert saved["run_count"] == 2 and saved["last_total"] == 5
    assert saved["last_run_at"] and saved["last_max_id"] == 5


# ─────────────── 결과 → 행동 ───────────────

def test_top_sources_rank_repeat_offenders(hunts):
    hunts.alert_store.rows = (_alerts(3, src="203.0.113.9")
                              + _alerts(1, start_id=50, src="198.51.100.7")
                              + _alerts(1, start_id=60, src="myhost"))
    created = hunts.create("반복 출발지", {"severity": "CRITICAL"})
    tops = hunts.run(created["id"])["top_sources"]
    assert tops[0] == {"ip": "203.0.113.9", "count": 3}
    assert "myhost" not in [t["ip"] for t in tops], "IP 가 아닌 값이 섞였다"


def test_promote_adds_to_watchlist(hunts):
    result = hunts.promote_to_watchlist("203.0.113.9", note="헌팅에서 승격",
                                        actor="analyst")
    assert result["ok"] is True
    assert hunts.watchlist.added[0][:2] == ("ip", "203.0.113.9")


def test_promote_failure_is_reported_not_raised(tmp_path):
    store = HuntStore(db_path=str(tmp_path / "h.db"),
                      alert_store=_FakeStore(), watchlist=_FakeWatchlist(fail=True))
    try:
        result = store.promote_to_watchlist("203.0.113.9")
        assert result["ok"] is False and "고장" in result["error"]
    finally:
        store.close()


def test_promote_without_watchlist_is_graceful(tmp_path):
    store = HuntStore(db_path=str(tmp_path / "h.db"), alert_store=_FakeStore())
    try:
        assert store.promote_to_watchlist("1.2.3.4")["ok"] is False
    finally:
        store.close()


# ─────────────── 시작 쿼리 · 수명주기 ───────────────

def test_starter_hunts_are_seeded_once(tmp_path):
    path = str(tmp_path / "seed.db")
    first = HuntStore(db_path=path, alert_store=_FakeStore())
    names = {h["name"] for h in first.list_all()}
    assert names == {h["name"] for h in STARTER_HUNTS}
    first.delete(first.list_all()[0]["id"])
    remaining = len(first.list_all())
    first.close()

    second = HuntStore(db_path=path, alert_store=_FakeStore())
    try:
        assert len(second.list_all()) == remaining, "사용자가 지운 것을 되살렸다"
    finally:
        second.close()


def test_every_starter_hunt_explains_itself():
    """헌팅 쿼리의 값어치는 조건이 아니라 '무엇을 왜 찾는가'에 있다."""
    for hunt in STARTER_HUNTS:
        assert hunt["description"].strip(), f"{hunt['name']}: 설명이 없다"
        assert hunt["filters"], f"{hunt['name']}: 조건이 없다"


def test_starter_hunts_use_only_allowed_filters():
    for hunt in STARTER_HUNTS:
        unknown = set(hunt["filters"]) - ALLOWED_FILTERS
        assert unknown == set(), f"{hunt['name']}: 알 수 없는 조건 {unknown}"


def test_update_and_delete(hunts):
    created = hunts.create("수정 대상", {"severity": "HIGH"})
    assert hunts.update(created["id"], name="새 이름",
                        filters={"severity": "CRITICAL"}) is True
    saved = hunts.get(created["id"])
    assert saved["name"] == "새 이름" and saved["filters"]["severity"] == "CRITICAL"
    assert hunts.delete(created["id"]) is True
    assert hunts.get(created["id"]) is None


def test_run_missing_hunt_returns_none(hunts):
    assert hunts.run(99999) is None


def test_broken_search_is_reported_not_raised(tmp_path):
    """저장된 조건이 낡아 search() 가 거부해도 콘솔이 죽으면 안 된다."""
    class _Picky:
        def search(self, **kw):
            raise TypeError("unexpected keyword")

    store = HuntStore(db_path=str(tmp_path / "h.db"), alert_store=_Picky())
    try:
        created = store.create("깨진 조건", {"severity": "HIGH"})
        result = store.run(created["id"])
        assert result["results"] == [] and "검색 조건 오류" in result["error"]
    finally:
        store.close()
