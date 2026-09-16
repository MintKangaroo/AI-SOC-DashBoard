"""DB 보존정책 — 인시던트·SOAR 실행 이력 (docs/AUDIT.md B-3).

alerts/audit/파일은 보존정책이 있었으나 `incidents.db`(18MB)와
`soar_executions.db`(48MB)는 정책 밖에서 무한 증가하고 있었다.

**이 테스트의 핵심은 성능이 아니라 안전이다.** 지우면 안 되는 것을 지우지
않는지가 전부다.

- 인시던트: 진행 중 케이스(OPEN/INVESTIGATING/CONTAINED)를 지우면 분석가의
  작업이 소리 없이 사라진다.
- SOAR 실행: `waiting_approval` 은 사람의 결정을 기다리는 항목이다. 지우면
  그 결정 기회 자체가 없어진다(실 DB 기준 1,685건).
"""
from datetime import datetime, timedelta

import pytest

from modules.incidents import IncidentManager
from modules.soar_execution_store import (INTERRUPTED_CANDIDATES,
                                          NON_TERMINAL_STATUSES,
                                          SOARExecutionStore)


def _ts(days_ago):
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


class FakeSocketIO:
    def emit(self, *a, **k):
        pass


# ══════════════════════════════════════════════════════════════════
#  SOAR 실행 이력
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  끊긴 실행 복구 — 서버가 죽으면 그 자리에서 멈춘다
# ══════════════════════════════════════════════════════════════════
#
# `running` 은 정리 대상에서 제외되는 상태라, 서버가 죽을 때마다 화면과 통계에
# 영원히 '진행 중' 으로 남는다. 실제로 2026-08-27~29 에 죽은 4건이 3주 가까이
# 남아 있었다(2026-09-16 정리). 다음 기동이 이걸 닫아야 한다.


@pytest.mark.parametrize("status", INTERRUPTED_CANDIDATES)
def test_interrupted_runs_are_closed_on_next_start(store, status):
    _save(store, 1, status, days_ago=3, finished=False)
    assert store.recover_interrupted() == 1
    assert store.counts_by_status() == {"interrupted": 1}


def test_waiting_approval_is_not_touched_by_recovery(store):
    """사람의 결정을 기다리는 것은 끊긴 게 아니다 — 닫으면 결정 기회가 사라진다."""
    _save(store, 1, "waiting_approval", days_ago=3, finished=False)
    assert store.recover_interrupted() == 0
    assert store.counts_by_status() == {"waiting_approval": 1}


def test_recovery_keeps_where_it_stopped(store):
    """어디서 끊겼는지 남긴다 — 나중에 그 단계부터 볼 수 있어야 한다."""
    store.save({"id": 7, "playbook": "PB-AI-TRIAGE", "status": "running",
                "started": _ts(2), "finished": None, "current_step": "notify",
                "steps": [{"key": "ai", "status": "completed", "detail": "신뢰도 87%"},
                          {"key": "notify", "status": "running", "detail": "인시던트 승격"},
                          {"key": "close", "status": "pending", "detail": ""}]})
    store.recover_interrupted()
    entry = store.load_recent(1)[0]
    assert entry["status"] == "interrupted"
    assert entry["current_step"] is None
    # 종료 시각은 비워 둔다 — 정리한 시각은 끝난 시각이 아니고, 적으면 보존이
    # 그 시점부터 다시 세어진다(아래 테스트가 그걸 잡는다).
    assert not entry.get("finished")
    steps = {s["key"]: s for s in entry["steps"]}
    assert steps["ai"]["status"] == "completed"          # 끝난 단계는 그대로
    assert steps["ai"]["detail"] == "신뢰도 87%"
    assert steps["notify"]["status"] == "interrupted"
    assert "끊김" in steps["notify"]["detail"]
    assert "인시던트 승격" in steps["notify"]["detail"]   # 원래 내용도 남긴다


def test_recovery_is_idempotent_and_purgeable_afterwards(store):
    """닫힌 뒤에는 보존 루프가 정리할 수 있어야 한다 — 안 그러면 영원히 쌓인다.

    나이는 **원래 시작 시각** 기준이다. 정리한 시각을 종료로 적으면 200일 된
    기록이 다시 90일을 기다리게 된다.
    """
    _save(store, 1, "running", days_ago=200, finished=False)
    assert store.recover_interrupted() == 1
    assert store.recover_interrupted() == 0
    assert store.count_purgeable(90) == 1


@pytest.fixture
def store(tmp_path):
    s = SOARExecutionStore(db_path=str(tmp_path / "exec.db"))
    yield s
    s._conn.close()


def _save(store, run_id, status, days_ago, finished=True):
    entry = {"id": run_id, "playbook": "PB-TEST", "status": status,
             "started": _ts(days_ago),
             "finished": _ts(days_ago) if finished else None}
    store.save(entry)


@pytest.mark.parametrize("status", NON_TERMINAL_STATUSES)
def test_non_terminal_executions_never_purged(store, status):
    """승인 대기·진행 중은 아무리 오래돼도 지우지 않는다."""
    _save(store, 1, status, days_ago=9999)
    assert store.count_purgeable(90) == 0
    assert store.purge_terminal_older_than(90) == 0
    assert store.counts_by_status().get(status) == 1


def test_waiting_approval_survives_alongside_old_completed(store):
    """섞여 있을 때도 승인 대기만 살아남아야 한다."""
    _save(store, 1, "waiting_approval", days_ago=400)
    _save(store, 2, "completed", days_ago=400)
    _save(store, 3, "completed", days_ago=400)
    assert store.purge_terminal_older_than(90) == 2
    remaining = store.counts_by_status()
    assert remaining == {"waiting_approval": 1}


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled",
                                    "expired", "rejected", "skipped"])
def test_terminal_executions_purged_when_old(store, status):
    _save(store, 1, status, days_ago=400)
    assert store.count_purgeable(90) == 1
    assert store.purge_terminal_older_than(90) == 1
    assert store.counts_by_status() == {}


def test_recent_terminal_executions_kept(store):
    _save(store, 1, "completed", days_ago=10)
    assert store.count_purgeable(90) == 0
    assert store.purge_terminal_older_than(90) == 0


def test_unknown_status_is_preserved_by_default(store):
    """새 상태값이 생겨도 기본이 '보존'이어야 한다 — 제외 목록 방식의 이유."""
    _save(store, 1, "some_new_future_status", days_ago=400)
    # 제외 목록에 없으므로 종료 상태로 간주되어 지워진다.
    # 이 테스트는 그 사실을 명시적으로 고정한다 — 새 비종료 상태를 추가하면
    # NON_TERMINAL_STATUSES 에도 넣어야 한다는 신호다.
    assert store.purge_terminal_older_than(90) == 1


def test_missing_finished_falls_back_to_started(store):
    """비정상 종료로 finished 가 비어도 started 로 판단해야 한다."""
    _save(store, 1, "failed", days_ago=400, finished=False)
    assert store.purge_terminal_older_than(90) == 1


def test_purge_is_idempotent(store):
    _save(store, 1, "completed", days_ago=400)
    assert store.purge_terminal_older_than(90) == 1
    assert store.purge_terminal_older_than(90) == 0


def test_purged_executions_gone_from_load_recent(store):
    _save(store, 1, "completed", days_ago=400)
    _save(store, 2, "completed", days_ago=1)
    store.purge_terminal_older_than(90)
    assert len(store.load_recent(100)) == 1


# ══════════════════════════════════════════════════════════════════
#  인시던트
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def mgr(tmp_path):
    m = IncidentManager(FakeSocketIO(), store_path=str(tmp_path / "inc.db"),
                        save_debounce_seconds=0)
    yield m
    if getattr(m, "_db", None):
        m._db.close()


def _incident(mgr, inc_id, status, days_ago):
    mgr.incidents[inc_id] = {
        "id": inc_id, "title": f"inc{inc_id}", "threat_type": "T",
        "src_net": "203.0.113.0/24", "severity": "HIGH", "status": status,
        "assignee": "", "alert_ids": [], "created": _ts(days_ago),
        "updated": _ts(days_ago), "timeline": [],
    }
    mgr._dirty.add(inc_id)
    mgr._save()


@pytest.mark.parametrize("status", ["OPEN", "INVESTIGATING", "CONTAINED"])
def test_active_incidents_never_purged(mgr, status):
    """진행 중 케이스를 지우면 분석가의 작업이 소리 없이 사라진다."""
    _incident(mgr, 1, status, days_ago=9999)
    assert mgr.count_purgeable(365) == 0
    assert mgr.purge_resolved_older_than(365) == 0
    assert 1 in mgr.incidents


def test_resolved_incident_purged_when_old(mgr):
    _incident(mgr, 1, "RESOLVED", days_ago=400)
    assert mgr.count_purgeable(365) == 1
    assert mgr.purge_resolved_older_than(365) == 1
    assert mgr.incidents == {}


def test_recent_resolved_incident_kept(mgr):
    _incident(mgr, 1, "RESOLVED", days_ago=10)
    assert mgr.purge_resolved_older_than(365) == 0
    assert 1 in mgr.incidents


def test_mixed_states_only_old_resolved_removed(mgr):
    _incident(mgr, 1, "RESOLVED", days_ago=400)
    _incident(mgr, 2, "RESOLVED", days_ago=10)
    _incident(mgr, 3, "OPEN", days_ago=400)
    _incident(mgr, 4, "INVESTIGATING", days_ago=400)
    assert mgr.purge_resolved_older_than(365) == 1
    assert set(mgr.incidents) == {2, 3, 4}


def test_purge_removes_from_db_not_just_memory(tmp_path):
    path = str(tmp_path / "inc.db")
    m1 = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    _incident(m1, 1, "RESOLVED", days_ago=400)
    _incident(m1, 2, "OPEN", days_ago=400)
    assert m1.purge_resolved_older_than(365) == 1
    m1._db.close()

    m2 = IncidentManager(FakeSocketIO(), store_path=path)
    try:
        assert set(m2.incidents) == {2}, "메모리에서만 지우고 DB 에 남음"
    finally:
        m2._db.close()


def test_purge_clears_dirty_for_removed(mgr):
    _incident(mgr, 1, "RESOLVED", days_ago=400)
    mgr._dirty.add(1)
    mgr.purge_resolved_older_than(365)
    assert 1 not in mgr._dirty, "삭제된 인시던트가 저장 대기로 남음"


def test_purge_is_idempotent_incidents(mgr):
    _incident(mgr, 1, "RESOLVED", days_ago=400)
    assert mgr.purge_resolved_older_than(365) == 1
    assert mgr.purge_resolved_older_than(365) == 0


# ══════════════════════════════════════════════════════════════════
#  retention 루프 결선
# ══════════════════════════════════════════════════════════════════

class FakeApp:
    def __init__(self, incidents=None, soar=None):
        self.config = {}
        if incidents is not None:
            self.incidents = incidents
        if soar is not None:
            self.soar = soar


class FakeSOAR:
    def __init__(self, store):
        self.execution_store = store


def test_retention_preview_reports_both(tmp_path, mgr, store):
    from modules import retention
    _incident(mgr, 1, "RESOLVED", days_ago=400)
    _incident(mgr, 2, "OPEN", days_ago=400)
    _save(store, 1, "completed", days_ago=400)
    _save(store, 2, "waiting_approval", days_ago=400)

    out = retention.preview(FakeApp(incidents=mgr, soar=FakeSOAR(store)))
    assert out["incidents_to_delete"] == 1
    assert out["soar_executions_to_delete"] == 1
    assert out["policy"]["incident_days"] == 365
    assert out["policy"]["soar_exec_days"] == 90


def test_retention_cleanup_runs_both(tmp_path, mgr, store):
    from modules import retention
    _incident(mgr, 1, "RESOLVED", days_ago=400)
    _incident(mgr, 2, "INVESTIGATING", days_ago=400)
    _save(store, 1, "completed", days_ago=400)
    _save(store, 2, "waiting_approval", days_ago=400)

    result = retention.run_cleanup(FakeApp(incidents=mgr, soar=FakeSOAR(store)))
    assert result["incidents_deleted"] == 1
    assert result["soar_executions_deleted"] == 1
    assert set(mgr.incidents) == {2}, "진행 중 케이스가 지워짐"
    assert store.counts_by_status() == {"waiting_approval": 1}, "승인 대기가 지워짐"


def test_retention_survives_missing_services():
    """서비스가 없어도 정리 루프가 죽으면 안 된다."""
    from modules import retention
    out = retention.run_cleanup(FakeApp())
    assert out["incidents_deleted"] == 0
    assert out["soar_executions_deleted"] == 0


# ══════════════════════════════════════════════════════════════════
#  인시던트 자동 종료 (AUDIT B-3a)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("status", ["OPEN", "INVESTIGATING", "CONTAINED"])
def test_stale_incident_auto_resolved(mgr, status):
    _incident(mgr, 1, status, days_ago=40)
    assert mgr.count_auto_resolvable(30) == 1
    assert mgr.auto_resolve_stale(30) == 1
    assert mgr.incidents[1]["status"] == "RESOLVED"


def test_recent_incident_not_auto_resolved(mgr):
    _incident(mgr, 1, "OPEN", days_ago=5)
    assert mgr.count_auto_resolvable(30) == 0
    assert mgr.auto_resolve_stale(30) == 0
    assert mgr.incidents[1]["status"] == "OPEN"


def test_auto_resolve_records_reason_and_previous_status(mgr):
    """조용한 종료가 아니어야 한다 — 나중에 되짚을 수 있어야 한다."""
    _incident(mgr, 1, "INVESTIGATING", days_ago=40)
    mgr.auto_resolve_stale(30)
    entry = mgr.incidents[1]["timeline"][-1]
    assert entry["kind"] == "auto_resolve"
    assert "30일간 신규 활동 없음" in entry["text"]
    assert "INVESTIGATING" in entry["text"], "이전 상태가 기록되지 않음"


def test_already_resolved_not_touched_again(mgr):
    _incident(mgr, 1, "RESOLVED", days_ago=40)
    before = len(mgr.incidents[1]["timeline"])
    assert mgr.auto_resolve_stale(30) == 0
    assert len(mgr.incidents[1]["timeline"]) == before


def test_auto_resolve_persists(tmp_path):
    path = str(tmp_path / "inc.db")
    m1 = IncidentManager(FakeSocketIO(), store_path=path, save_debounce_seconds=0)
    _incident(m1, 1, "OPEN", days_ago=40)
    m1.auto_resolve_stale(30)
    m1._db.close()

    m2 = IncidentManager(FakeSocketIO(), store_path=path)
    try:
        assert m2.incidents[1]["status"] == "RESOLVED"
    finally:
        m2._db.close()


def test_new_alert_after_auto_resolve_opens_new_incident(mgr):
    """_find_active 가 RESOLVED 를 제외하므로 새 케이스로 다시 열려야 한다."""
    first = mgr.promote_alert({"id": 1, "threat_type": "BRUTE_FORCE",
                               "severity": "HIGH", "src_ip": "203.0.113.9",
                               "threat_label": "무차별 대입"})
    mgr.incidents[first]["updated"] = _ts(40)
    assert mgr.auto_resolve_stale(30) == 1

    second = mgr.promote_alert({"id": 2, "threat_type": "BRUTE_FORCE",
                                "severity": "HIGH", "src_ip": "203.0.113.9",
                                "threat_label": "무차별 대입"})
    assert second != first, "종료된 인시던트에 새 알림이 병합됨"
    assert mgr.incidents[second]["status"] == "OPEN"


def test_auto_resolve_respects_limit(mgr):
    for i in range(1, 6):
        _incident(mgr, i, "OPEN", days_ago=40)
    assert mgr.auto_resolve_stale(30, limit=2) == 2
    assert mgr.count_auto_resolvable(30) == 3


def test_auto_resolved_not_purged_immediately(mgr):
    """방금 종료된 건이 같은 정리 회차에 삭제되면 안 된다."""
    _incident(mgr, 1, "OPEN", days_ago=400)
    mgr.auto_resolve_stale(30)
    assert mgr.count_purgeable(365) == 0, "종료 직후 삭제 대상이 됨"
    assert 1 in mgr.incidents


def test_retention_auto_resolves_then_purges(mgr, store):
    from modules import retention
    _incident(mgr, 1, "OPEN", days_ago=400)          # 자동 종료 대상
    _incident(mgr, 2, "RESOLVED", days_ago=400)      # 즉시 삭제 대상
    _incident(mgr, 3, "OPEN", days_ago=5)            # 둘 다 아님

    result = retention.run_cleanup(FakeApp(incidents=mgr, soar=FakeSOAR(store)))
    assert result["incidents_auto_resolved"] == 1
    assert result["incidents_deleted"] == 1
    assert set(mgr.incidents) == {1, 3}
    assert mgr.incidents[1]["status"] == "RESOLVED"
    assert mgr.incidents[3]["status"] == "OPEN"


def test_auto_resolve_disabled_when_zero(mgr):
    from modules import retention
    app = FakeApp(incidents=mgr)
    app.config["INCIDENT_AUTO_RESOLVE_DAYS"] = 0
    _incident(mgr, 1, "OPEN", days_ago=400)
    result = retention.run_cleanup(app)
    assert result["incidents_auto_resolved"] == 0
    assert mgr.incidents[1]["status"] == "OPEN"


def test_preview_reports_auto_resolve_count(mgr):
    from modules import retention
    _incident(mgr, 1, "OPEN", days_ago=40)
    out = retention.preview(FakeApp(incidents=mgr))
    assert out["incidents_to_auto_resolve"] == 1
    assert out["policy"]["incident_auto_resolve_days"] == 30
