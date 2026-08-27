"""알림 중복제거·억제 레이어 테스트.

핵심 불변식: **어떤 알림도 조용히 사라지지 않는다.** 병합되거나 억제된 이벤트는
전부 `suppressed_events` 에 원문째 남아 복구 조회가 가능해야 한다.
"""
import time

import pytest

from modules.alert_dedup import (AlertDeduplicator, extract_rule_id,
                                 fingerprint, normalize_description)
from modules.threat_detector import ThreatDetector


class FakeSocketIO:
    def __init__(self):
        self.events = []

    def emit(self, event, data=None, **kwargs):
        self.events.append((event, data))

    def of(self, *a, **k):
        return self


def _alert(threat_type="BRUTE_FORCE", severity="HIGH", src="203.0.113.5",
           dst="192.168.1.5", desc="SSH 무차별 대입 실패 50회", details=None):
    return {"threat_type": threat_type, "severity": severity, "src_ip": src,
            "dst_ip": dst, "description": desc, "details": details or {},
            "timestamp": "2026-08-27 12:00:00"}


@pytest.fixture
def dedup(tmp_path):
    """순수 dedup 검증용 — 스톰 임계값을 높여 스톰 전환이 끼어들지 않게 한다."""
    d = AlertDeduplicator(
        config={"DEDUP_WINDOW_SECONDS": 300, "DEDUP_STORM_THRESHOLD": 100000},
        db_path=str(tmp_path / "dedup.db"))
    yield d
    d.close()


# ─────────── 핑거프린트 ───────────

def test_normalize_description_strips_variable_parts():
    a = normalize_description("SSH 실패 50회 from 203.0.113.5")
    b = normalize_description("SSH 실패 128회 from 198.51.100.9")
    assert a == b, f"{a!r} != {b!r}"


def test_fingerprint_stable_for_same_shape():
    f1 = fingerprint("BRUTE_FORCE", "203.0.113.5", "192.168.1.5", "실패 50회")
    f2 = fingerprint("BRUTE_FORCE", "203.0.113.5", "192.168.1.5", "실패 700회")
    assert f1 == f2


def test_fingerprint_differs_by_source_and_type():
    base = ("BRUTE_FORCE", "203.0.113.5", "192.168.1.5", "실패 50회")
    assert fingerprint(*base) != fingerprint("PORT_SCAN", *base[1:])
    assert fingerprint(*base) != fingerprint(base[0], "198.51.100.1", *base[2:])


def test_fingerprint_handles_non_ip_sources():
    """실측상 src_ip 가 None(SIGMA_MATCH) 이나 호스트명(EDR_THREAT)인 알림이 26%다."""
    f_none = fingerprint("SIGMA_MATCH", None, None, "규칙 매치")
    f_host = fingerprint("EDR_THREAT", "mintkangaroo", None, "의심 프로세스")
    assert f_none and f_host and f_none != f_host
    assert f_none == fingerprint("SIGMA_MATCH", "", "None", "규칙 매치")


def test_extract_rule_id_reads_each_source_convention():
    assert extract_rule_id({"rule_id": "sigma-001"}) == "sigma-001"
    assert extract_rule_id({"sid": "254"}) == "254"
    assert extract_rule_id({"service": "SSH"}) == "SSH"
    assert extract_rule_id({"category": "web_attack"}) == "web_attack"
    assert extract_rule_id({}) == ""
    assert extract_rule_id(None) == ""


def test_different_rule_ids_do_not_merge():
    """같은 유형·출발지라도 룰이 다르면 별개 알림이어야 한다."""
    a = fingerprint("SIGMA_MATCH", "host", None, "매치", {"rule_id": "A"})
    b = fingerprint("SIGMA_MATCH", "host", None, "매치", {"rule_id": "B"})
    assert a != b


# ─────────── 요구사항 1: 동일 이벤트 100건 → 알림 1건 + count 100 ───────────

def test_hundred_identical_events_yield_one_alert_with_count(dedup):
    results = [dedup.evaluate(_alert()) for _ in range(100)]
    passed = [r for r in results if r["action"] == "pass"]
    merged = [r for r in results if r["action"] == "duplicate"]
    assert len(passed) == 1, f"통과 알림이 1건이 아님: {len(passed)}"
    assert len(merged) == 99
    assert merged[-1]["count"] == 100
    # 병합된 99건이 전부 보관되어야 한다
    rows, total = dedup.suppressed(limit=200)
    assert total == 99
    assert all(r["kind"] == "duplicate" for r in rows)


# ─────────── 요구사항 2: 윈도우 만료 후 재발생 → 새 알림 ───────────

def test_new_alert_after_window_expires(tmp_path):
    d = AlertDeduplicator(config={"DEDUP_WINDOW_SECONDS": 0.3},
                          db_path=str(tmp_path / "d.db"))
    try:
        assert d.evaluate(_alert())["action"] == "pass"
        assert d.evaluate(_alert())["action"] == "duplicate"
        time.sleep(0.35)
        again = d.evaluate(_alert())
        assert again["action"] == "pass", "윈도우가 지났는데 병합됨"
        assert again["count"] == 1, "윈도우 만료 후 카운트가 이어짐"
    finally:
        d.close()


# ─────────── 요구사항 3: CRITICAL 은 억제 대상에서 제외 ───────────

def test_critical_is_exempt_from_suppression_rules(dedup):
    dedup.add_rule("스캐너", threat_type="PORT_SCAN", reason="알려진 스캐너")
    high = dedup.evaluate(_alert(threat_type="PORT_SCAN", severity="HIGH"))
    crit = dedup.evaluate(_alert(threat_type="PORT_SCAN", severity="CRITICAL",
                                 src="198.51.100.77"))
    assert high["action"] == "suppress"
    assert crit["action"] != "suppress", "CRITICAL 이 규칙으로 억제됨"


def test_critical_still_participates_in_dedup(dedup):
    """dedup 은 정보를 잃지 않으므로 CRITICAL 에도 적용한다(카운트 병합)."""
    first = dedup.evaluate(_alert(severity="CRITICAL"))
    second = dedup.evaluate(_alert(severity="CRITICAL"))
    assert first["action"] == "pass"
    assert second["action"] == "duplicate" and second["count"] == 2


# ─────────── 요구사항 4: 억제 규칙이 다른 룰까지 삼키지 않을 것 ───────────

def test_suppression_rule_does_not_swallow_other_threat_types(dedup):
    dedup.add_rule("스캐너만", threat_type="PORT_SCAN", reason="노이즈")
    assert dedup.evaluate(_alert(threat_type="PORT_SCAN", severity="LOW"))["action"] == "suppress"
    assert dedup.evaluate(_alert(threat_type="BRUTE_FORCE", severity="LOW"))["action"] == "pass"


def test_suppression_rule_scoped_by_source_prefix(dedup):
    dedup.add_rule("내부스캐너", src_prefix="10.0.0.", reason="자산 스캐너")
    assert dedup.evaluate(_alert(severity="LOW", src="10.0.0.9"))["action"] == "suppress"
    assert dedup.evaluate(_alert(severity="LOW", src="203.0.113.9"))["action"] == "pass"


def test_suppression_rule_scoped_by_rule_id(dedup):
    dedup.add_rule("SID254", rule_id="254", reason="Tailscale DNS 오탐")
    hit = _alert(severity="LOW", details={"sid": "254"})
    miss = _alert(severity="LOW", src="198.51.100.3", details={"sid": "999"})
    assert dedup.evaluate(hit)["action"] == "suppress"
    assert dedup.evaluate(miss)["action"] == "pass"


def test_broken_regex_rule_does_not_swallow_alerts(dedup):
    """깨진 규칙이 알림을 삼키면 조용한 누락이 된다."""
    dedup.add_rule("정상", desc_regex="무차별", reason="테스트")
    # DB 에 직접 잘못된 정규식을 넣어 런타임 방어를 검증
    with dedup._lock:
        dedup._conn.execute(
            "UPDATE suppression_rules SET desc_regex='[unclosed' WHERE name='정상'")
        dedup._conn.commit()
    assert dedup.evaluate(_alert(severity="LOW"))["action"] == "pass"


def test_disabled_rule_has_no_effect(dedup):
    rid = dedup.add_rule("스캐너", threat_type="PORT_SCAN")
    dedup.set_rule_enabled(rid, False)
    assert dedup.evaluate(_alert(threat_type="PORT_SCAN", severity="LOW"))["action"] == "pass"


def test_add_rule_rejects_invalid_regex(dedup):
    with pytest.raises(Exception):
        dedup.add_rule("깨진규칙", desc_regex="[unclosed")


# ─────────── 요구사항 5: 억제된 알림이 복구 조회 가능 ───────────

def test_suppressed_events_are_recoverable_with_payload(dedup):
    dedup.add_rule("스캐너", threat_type="PORT_SCAN", reason="알려진 스캐너")
    original = _alert(threat_type="PORT_SCAN", severity="MEDIUM",
                      desc="포트 스캔 40포트", details={"ports": 40})
    dedup.evaluate(original)
    rows, total = dedup.suppressed(kind="suppressed")
    assert total == 1
    saved = rows[0]
    assert saved["payload"]["description"] == "포트 스캔 40포트"
    assert saved["payload"]["details"]["ports"] == 40
    assert "스캐너" in saved["reason"]


def test_suppressed_query_filters_by_parent_alert(dedup):
    first = dedup.evaluate(_alert())
    dedup.note_alert_id(first["fingerprint"], 42)
    dedup.evaluate(_alert())
    dedup.evaluate(_alert())
    rows, total = dedup.suppressed(parent_alert=42)
    assert total == 2 and all(r["parent_alert"] == 42 for r in rows)


# ─────────── 스톰 모드 ───────────

def test_storm_mode_emits_single_summary(tmp_path):
    d = AlertDeduplicator(
        config={"DEDUP_WINDOW_SECONDS": 300, "DEDUP_STORM_THRESHOLD": 10,
                "DEDUP_STORM_WINDOW_SECONDS": 60, "DEDUP_STORM_SUMMARY_SECONDS": 999},
        db_path=str(tmp_path / "d.db"))
    try:
        actions = [d.evaluate(_alert())["action"] for _ in range(60)]
        assert actions[0] == "pass"
        assert actions.count("storm") == 1, f"요약 알림이 1건이 아님: {actions.count('storm')}"
        assert actions.count("duplicate") == 58
        stats = d.get_stats()
        assert stats["storms"] == 1 and stats["active_storms"] == 1
    finally:
        d.close()


def test_storm_events_are_still_recorded(tmp_path):
    """스톰 중에도 원문 보관은 계속되어야 한다."""
    d = AlertDeduplicator(
        config={"DEDUP_STORM_THRESHOLD": 5, "DEDUP_STORM_SUMMARY_SECONDS": 999},
        db_path=str(tmp_path / "d.db"))
    try:
        for _ in range(30):
            d.evaluate(_alert())
        _, total = d.suppressed(limit=1)
        # 30건 = 최초 통과 1 + 스톰 요약 통과 1 + 병합 28.
        # 통과분 2건은 알림이 되므로 보관 대상은 병합된 28건이다.
        assert total == 28, f"스톰 중 보관 누락: {total}"
    finally:
        d.close()


# ─────────── 지표 ───────────

def test_stats_expose_dedup_and_suppression_rates(dedup):
    dedup.add_rule("스캐너", threat_type="PORT_SCAN")
    for _ in range(9):
        dedup.evaluate(_alert())
    dedup.evaluate(_alert(threat_type="PORT_SCAN", severity="LOW"))
    s = dedup.get_stats()
    assert s["seen"] == 10
    assert s["deduplicated"] == 8 and s["suppressed"] == 1
    assert s["dedup_rate"] == 80.0 and s["suppression_rate"] == 10.0
    assert s["reduction_rate"] == 90.0
    assert s["window_seconds"] == 300


def test_disabled_dedup_passes_everything(tmp_path):
    d = AlertDeduplicator(config={"DEDUP_ENABLED": "False"},
                          db_path=str(tmp_path / "d.db"))
    try:
        assert all(d.evaluate(_alert())["action"] == "pass" for _ in range(5))
        assert d.get_stats()["deduplicated"] == 0
    finally:
        d.close()


def test_purge_older_than_keeps_recent(dedup):
    for _ in range(3):
        dedup.evaluate(_alert())
    assert dedup.purge_older_than(365) == 0     # 방금 것은 남는다
    _, total = dedup.suppressed()
    assert total == 2


# ─────────── ThreatDetector 결선 ───────────

@pytest.fixture
def detector(tmp_path):
    sio = FakeSocketIO()
    td = ThreatDetector(sio, config={}, store_path=str(tmp_path / "alerts.db"))
    layer = AlertDeduplicator(
        config={"DEDUP_WINDOW_SECONDS": 300, "DEDUP_STORM_THRESHOLD": 100000},
        db_path=str(tmp_path / "dedup.db"))
    td.dedup = layer
    yield td, sio
    layer.close()          # td.dedup 은 테스트가 교체할 수 있으므로 원본을 닫는다


def test_detector_emits_one_alert_and_then_dedup_updates(detector):
    td, sio = detector
    for _ in range(5):
        td.report_alert("BRUTE_FORCE", "HIGH", "203.0.113.5", "192.168.1.5",
                        "SSH 무차별 대입 실패 50회")
    new_alerts = [d for e, d in sio.events if e == "new_alert"]
    updates = [d for e, d in sio.events if e == "alert_dedup"]
    assert len(new_alerts) == 1, f"새 알림이 1건이 아님: {len(new_alerts)}"
    assert len(updates) == 4
    assert updates[-1]["count"] == 5
    assert updates[-1]["alert_id"] == new_alerts[0]["id"]


def test_detector_updates_parent_alert_details(detector):
    td, _ = detector
    for _ in range(3):
        td.report_alert("BRUTE_FORCE", "HIGH", "203.0.113.5", "192.168.1.5", "실패 50회")
    parent = td.alerts[-1]
    assert parent.details["dedup"]["count"] == 3
    assert parent.details["dedup"]["first_seen"]
    # 영속 저장본도 갱신되어야 한다
    rows, _ = td.store.search(limit=10)
    assert rows[0]["details"]["dedup"]["count"] == 3


def test_detector_stats_count_deduplicated(detector):
    td, _ = detector
    for _ in range(4):
        td.report_alert("BRUTE_FORCE", "HIGH", "203.0.113.5", "192.168.1.5", "실패 50회")
    assert td.stats["deduplicated"] == 3
    assert td.stats["total_alerts"] == 1


def test_detector_passes_alert_when_dedup_missing(tmp_path):
    """dedup 레이어가 없어도 알림이 사라지면 안 된다."""
    sio = FakeSocketIO()
    td = ThreatDetector(sio, config={}, store_path=str(tmp_path / "a.db"))
    td.dedup = None
    for _ in range(3):
        td.report_alert("BRUTE_FORCE", "HIGH", "203.0.113.5", "192.168.1.5", "실패")
    assert len([d for e, d in sio.events if e == "new_alert"]) == 3


def test_detector_passes_alert_when_dedup_raises(detector):
    """dedup 이 깨지면 중복이 나오더라도 알림은 통과시킨다 — 유실이 더 나쁘다."""
    td, sio = detector

    class Broken:
        def evaluate(self, alert):
            raise RuntimeError("고장")

        def note_alert_id(self, *a):
            pass

    td.dedup = Broken()
    for _ in range(3):
        td.report_alert("BRUTE_FORCE", "HIGH", "203.0.113.5", "192.168.1.5", "실패")
    assert len([d for e, d in sio.events if e == "new_alert"]) == 3


def test_detector_different_sources_are_not_merged(detector):
    td, sio = detector
    td.report_alert("BRUTE_FORCE", "HIGH", "203.0.113.5", "192.168.1.5", "실패 50회")
    td.report_alert("BRUTE_FORCE", "HIGH", "198.51.100.9", "192.168.1.5", "실패 50회")
    assert len([d for e, d in sio.events if e == "new_alert"]) == 2
