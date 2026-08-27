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
import json
from datetime import datetime, timedelta

import pytest

from modules.incidents import IncidentManager
from modules.soar_execution_store import (NON_TERMINAL_STATUSES,
                                          SOARExecutionStore)


def _ts(days_ago):
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


class FakeSocketIO:
    def emit(self, *a, **k):
        pass


# ══════════════════════════════════════════════════════════════════
#  SOAR 실행 이력
# ══════════════════════════════════════════════════════════════════

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
