"""차단 결정 재현 로그 (docs/AUDIT.md 3단계 제안 C).

자동 차단은 **되돌리기 어려운 조치**인데 그 근거가 휘발성이었다.
`soar_executions.db` 에 실행 스냅샷은 있었지만 각 입력 신호의 그 시점 값이 없어,
사후에 "왜 이 IP 가 차단되었나"를 완전히 재구성할 수 없었다.

이 테스트가 지키는 불변식 셋:

1. **기록된 결정이 곧 실제 결정이다.** 로그를 위해 판정을 다시 계산하면 로그와
   행동이 갈라질 수 있고, 그런 로그는 없느니만 못하다.
2. **차단하지 않은 결정도 남는다.** 실무에서 더 자주 묻는 질문은 "왜 안 막았나"다.
3. **기록 실패가 차단 파이프라인을 멈추지 않는다.** 감사 로그를 못 남긴다고
   보안 조치를 중단하는 건 본말전도다.
"""
import sqlite3

import pytest

from modules.block_decision import (GATE_LABELS, BlockDecisionLog,
                                    blocking_reasons, evaluate_gates)

PASSING = dict(
    playbook_enabled=True, auto_block=True, severity="CRITICAL",
    is_true_positive=True, confidence=98, min_confidence=95,
    evidence=["snort_signature", "abuseipdb_90"], require_corroboration=True,
    is_demo=False, is_external=True,
)


def _log(tmp_path, **kw):
    return BlockDecisionLog(db_path=str(tmp_path / "decisions.db"), **kw)


# ─────────────── 게이트 판정 ───────────────

def test_all_gates_pass_blocks():
    blocked, gates = evaluate_gates(**PASSING)
    assert blocked is True
    assert blocking_reasons(gates) == []
    assert {g["id"] for g in gates} == set(GATE_LABELS)


@pytest.mark.parametrize("override,expected_blocker", [
    ({"confidence": 60}, "confidence"),
    ({"severity": "HIGH"}, "severity_critical"),
    ({"is_true_positive": False}, "verdict_true_positive"),
    ({"evidence": ["snort_signature"]}, "corroboration"),
    ({"is_demo": True}, "not_demo"),
    ({"is_external": False}, "external_ip"),
    ({"auto_block": False}, "auto_block_on"),
    ({"playbook_enabled": False}, "playbook_enabled"),
])
def test_each_gate_can_block_on_its_own(override, expected_blocker):
    """어떤 게이트가 막았는지가 곧 '왜 안 막았나'의 답이다."""
    blocked, gates = evaluate_gates(**{**PASSING, **override})
    assert blocked is False
    assert expected_blocker in blocking_reasons(gates)


def test_corroboration_is_skipped_when_not_required():
    blocked, _ = evaluate_gates(**{**PASSING, "evidence": [],
                                   "require_corroboration": False})
    assert blocked is True


def test_gate_records_actual_and_required_values():
    """숫자를 남겨야 '얼마나 모자랐는지'를 알 수 있다."""
    _, gates = evaluate_gates(**{**PASSING, "confidence": 60})
    gate = next(g for g in gates if g["id"] == "confidence")
    assert gate["actual"] == 60 and gate["required"] == 95


# ─────────────── 기록 ───────────────

def test_records_both_blocked_and_skipped(tmp_path):
    log = _log(tmp_path)
    try:
        for conf, blocked in ((98, True), (60, False)):
            ok, gates = evaluate_gates(**{**PASSING, "confidence": conf})
            assert ok is blocked
            log.record(alert_id=1, src_ip="203.0.113.5", blocked=ok, gates=gates,
                       signals={"confidence": conf}, thresholds={})
        rows = log.recent()
        assert [r["blocked"] for r in rows] == [False, True]   # 최신순
        skipped = rows[0]
        assert "confidence" in skipped["blocked_by"], "왜 안 막았는지가 없다"
    finally:
        log.close()


def test_stats_rank_what_blocks_most(tmp_path):
    """무엇이 차단을 가장 자주 막았는가 — 임계값 튜닝의 출발점."""
    log = _log(tmp_path)
    try:
        for _ in range(3):
            _, gates = evaluate_gates(**{**PASSING, "confidence": 60})
            log.record(alert_id=1, src_ip="1.2.3.4", blocked=False, gates=gates,
                       signals={}, thresholds={})
        _, gates = evaluate_gates(**{**PASSING, "is_external": False})
        log.record(alert_id=2, src_ip="10.0.0.1", blocked=False, gates=gates,
                   signals={}, thresholds={})
        stats = log.stats()
        assert stats["total"] == 4 and stats["blocked"] == 0 and stats["skipped"] == 4
        assert stats["top_blockers"][0]["id"] == "confidence"
        assert stats["top_blockers"][0]["count"] == 3
    finally:
        log.close()


def test_recording_failure_does_not_raise(tmp_path):
    """감사 로그를 못 남긴다고 차단 파이프라인을 멈추면 안 된다."""
    log = _log(tmp_path)
    log._conn.close()          # 저장소를 고장낸다
    assert log.record(alert_id=1, src_ip="1.2.3.4", blocked=True, gates=[],
                      signals={}, thresholds={}) is None


def test_corrupt_json_does_not_break_listing(tmp_path):
    log = _log(tmp_path)
    try:
        _, gates = evaluate_gates(**PASSING)
        log.record(alert_id=1, src_ip="1.2.3.4", blocked=True, gates=gates,
                   signals={}, thresholds={})
        with log._lock:
            log._conn.execute("UPDATE decisions SET signals = '{ 깨진'")
            log._conn.commit()
        assert log.recent()[0]["signals"] == {}
    finally:
        log.close()


# ─────────────── 재생 ───────────────

def test_replay_flips_when_threshold_lowered(tmp_path):
    log = _log(tmp_path)
    try:
        _, gates = evaluate_gates(**{**PASSING, "confidence": 60})
        did = log.record(alert_id=1, src_ip="203.0.113.5", blocked=False, gates=gates,
                         signals={"confidence": 60, "evidence": PASSING["evidence"]},
                         thresholds={"min_block_confidence": 95,
                                     "require_corroboration": True, "auto_block": True})
        same = log.replay(did)
        assert same["replayed"]["blocked"] is False and same["changed"] is False
        lowered = log.replay(did, min_confidence=50)
        assert lowered["replayed"]["blocked"] is True
        assert lowered["changed"] is True
        assert lowered["original"]["blocked"] is False
    finally:
        log.close()


def test_replay_does_not_mutate_the_record(tmp_path):
    """재생은 조회 전용이다 — 원본 결정을 고쳐 쓰면 감사 기록이 아니게 된다."""
    log = _log(tmp_path)
    try:
        _, gates = evaluate_gates(**{**PASSING, "confidence": 60})
        did = log.record(alert_id=1, src_ip="1.2.3.4", blocked=False, gates=gates,
                         signals={"confidence": 60, "evidence": []}, thresholds={
                             "min_block_confidence": 95, "require_corroboration": True,
                             "auto_block": True})
        before = log.get(did)
        log.replay(did, min_confidence=10, require_corroboration=False)
        assert log.get(did) == before
    finally:
        log.close()


def test_replay_of_missing_record_returns_none(tmp_path):
    log = _log(tmp_path)
    try:
        assert log.replay(9999) is None
    finally:
        log.close()


# ─────────────── 보존 ───────────────

def test_purge_only_removes_expired(tmp_path):
    log = _log(tmp_path, retention_days=365)
    try:
        _, gates = evaluate_gates(**PASSING)
        log.record(alert_id=1, src_ip="1.2.3.4", blocked=True, gates=gates,
                   signals={}, thresholds={})
        log.record(alert_id=2, src_ip="5.6.7.8", blocked=True, gates=gates,
                   signals={}, thresholds={})
        with log._lock:
            log._conn.execute("UPDATE decisions SET ts='2000-01-01 00:00:00' WHERE id=1")
            log._conn.commit()
        assert log.purge_older_than() == 1
        assert [r["id"] for r in log.recent()] == [2]
    finally:
        log.close()


def test_uses_wal_like_the_other_hot_stores(tmp_path):
    log = _log(tmp_path)
    try:
        conn = sqlite3.connect(str(tmp_path / "decisions.db"))
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        conn.close()
    finally:
        log.close()


# ─────────────── SOAR 통합: 기록이 곧 실제 결정인가 ───────────────

class _Silent:
    def emit(self, *a, **k):
        pass


def _soar(tmp_path, **cfg):
    from modules.soar import SOAREngine

    engine = SOAREngine(_Silent(), config={
        "SOAR_BLOCK_MODE": "simulate", "SOAR_AUTO_BLOCK": True,
        "SOAR_APPROVAL_REQUIRED": False, "SOAR_MIN_BLOCK_CONFIDENCE": 95,
        "SOAR_REQUIRE_CORROBORATION": True, **cfg},
        blocklist_path=str(tmp_path / "blocklist.txt"),
        execution_db_path=str(tmp_path / "exec.db"))
    engine.block_decisions = BlockDecisionLog(db_path=str(tmp_path / "dec.db"))
    return engine


def _alert(**kw):
    base = {"id": 1, "severity": "CRITICAL", "src_ip": "203.0.113.77",
            "dst_ip": "10.0.0.5", "threat_type": "MALWARE_C2", "confidence": 0.98,
            "details": {"evidence": ["snort_signature", "abuseipdb_90"],
                        "ip_reputation": {"score": 95, "source": "abuseipdb"}}}
    base.update(kw)
    return base


# 안전장치를 통과하는 공인 IP. block_mode=simulate 라 실제 방화벽은 건드리지 않는다.
PUBLIC_IP = "93.184.216.34"


def _blocked_ips(engine):
    return [row["ip"] for row in engine.get_status()["blocked_ips"]]


def test_recorded_decision_matches_what_soar_actually_did(tmp_path):
    """로그와 행동이 갈라지면 그 로그는 없느니만 못하다."""
    engine = _soar(tmp_path)
    try:
        engine._apply_triage(_alert(src_ip=PUBLIC_IP), True, 98, "판정", ai=True)
        record = engine.block_decisions.recent()[0]
        assert record["blocked"] is True and record["outcome"] == "blocked"
        assert PUBLIC_IP in _blocked_ips(engine), "기록은 차단인데 실제로 안 막았다"
    finally:
        engine.block_decisions.close()


def test_low_confidence_is_recorded_as_not_attempted(tmp_path):
    engine = _soar(tmp_path)
    try:
        engine._apply_triage(_alert(src_ip=PUBLIC_IP, confidence=0.60), True, 60,
                             "확신 낮음", ai=True)
        record = engine.block_decisions.recent()[0]
        assert record["blocked"] is False
        assert record["gates_passed"] is False
        assert record["outcome"] == "gates_not_met"
        assert PUBLIC_IP not in _blocked_ips(engine)
    finally:
        engine.block_decisions.close()


def test_safety_net_outranks_the_gates_and_is_recorded(tmp_path):
    """게이트를 다 통과해도 안전장치가 막으면 '차단됨'이 아니다.

    TEST-NET(203.0.113.0/24)은 공인 IP 가 아니라 안전장치가 거부한다. 이때
    `gates_passed=True` 인데 `blocked=False` 다 — 그 둘을 한 필드로 뭉뚱그리면
    로그가 '차단됨'이라 말하고 실제로는 아닌 상태가 된다.
    """
    engine = _soar(tmp_path)
    try:
        engine._apply_triage(_alert(), True, 98, "판정", ai=True)   # TEST-NET IP
        record = engine.block_decisions.recent()[0]
        assert record["gates_passed"] is True
        assert record["blocked"] is False
        assert record["outcome"] == "prevented_by_safety"
        assert record["blocked_by"] == [], "게이트는 모두 통과했어야 한다"
    finally:
        engine.block_decisions.close()


def test_approval_queue_is_not_recorded_as_blocked(tmp_path):
    """승인 대기는 '사람의 결정을 기다리는 중'이지 차단이 아니다."""
    engine = _soar(tmp_path, SOAR_APPROVAL_REQUIRED=True)
    try:
        engine._apply_triage(_alert(src_ip=PUBLIC_IP), True, 98, "판정", ai=True)
        record = engine.block_decisions.recent()[0]
        assert record["gates_passed"] is True
        assert record["blocked"] is False
        assert record["outcome"] == "queued_for_approval"
        assert PUBLIC_IP not in _blocked_ips(engine)
    finally:
        engine.block_decisions.close()


def test_skipped_decision_records_why(tmp_path):
    """'왜 안 막았나'가 남아야 한다 — 실무에서 더 자주 묻는 질문이다."""
    engine = _soar(tmp_path)
    try:
        engine._apply_triage(
            _alert(src_ip=PUBLIC_IP, confidence=0.60,
                   details={"evidence": ["snort_signature"], "ip_reputation": {}}),
            True, 60, "확신 낮음", ai=True)
        record = engine.block_decisions.recent()[0]
        assert record["blocked"] is False
        assert set(record["blocked_by"]) >= {"confidence", "corroboration"}
        assert record["signals"]["confidence"] == 60
    finally:
        engine.block_decisions.close()


def test_signals_snapshot_carries_ai_evidence_without_the_prompt(tmp_path):
    """제안 #6 — AI 근거는 남기되 프롬프트 전문은 담지 않는다(알림 사본이 된다)."""
    engine = _soar(tmp_path)
    try:
        engine._apply_triage(_alert(src_ip=PUBLIC_IP), True, 98,
                             "C2 비콘 확인 — 평판 95점", ai=True)
        signals = engine.block_decisions.recent()[0]["signals"]
        assert signals["verdict_by"] == "AI"
        assert "C2 비콘" in signals["ai_summary"]
        assert signals["ip_reputation"]["score"] == 95
        assert signals["evidence"] == ["abuseipdb_90", "snort_signature"]
        assert "prompt" not in signals
    finally:
        engine.block_decisions.close()


def test_soar_works_when_decision_log_is_absent(tmp_path):
    """결정 로그가 없어도 차단 파이프라인은 그대로 돈다."""
    engine = _soar(tmp_path)
    engine.block_decisions.close()
    engine.block_decisions = None
    engine._apply_triage(_alert(), True, 98, "판정", ai=True)   # 예외가 나면 안 된다
