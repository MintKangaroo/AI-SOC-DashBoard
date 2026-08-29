"""OCSF 내보내기 (docs/AUDIT.md 3단계 제안 #1).

감사는 **OCSF 전면 도입을 비추천**했다 — 40개 모듈을 표준 클래스에 매핑하는
대공사인데 얻는 게 "표준을 따른다"는 사실뿐이고 화면엔 변화가 없다. 대신
권고된 것이 **내보내기 계층 하나**다. 내부 구조는 그대로 두고 밖으로 나갈 때만
표준 형태로 바꾼다.

**표준 준수를 자기 코드로 검증하면 그건 검증이 아니다.** 내가 만든 매핑을
내가 만든 어서션으로 확인하면 둘 다 같은 오해를 공유한다. 그래서 독립
라이브러리(`py-ocsf-models`)로 검증한다 — 실제로 이 라이브러리가 `analytic.uid`
누락을 잡아냈다.

**과장하지 않는다**: 이건 OCSF 핵심 필드 **부분집합**이다. 인증받은 완전 매핑이
아니고, cloud·security_control 프로필은 적용하지 않는다(온프렘이라 맞지 않는다).
"""
import pytest

from modules.ocsf_export import (CATEGORY_UID_FINDINGS, CLASS_UID_DETECTION_FINDING,
                                 OCSF_VERSION, SEVERITY_ID, STATUS_ID,
                                 alert_to_ocsf, alerts_to_ocsf)

ocsf_models = pytest.importorskip("py_ocsf_models",
                                  reason="py-ocsf-models 미설치 — 독립 검증 불가")
from py_ocsf_models.events.findings.detection_finding import (  # noqa: E402
    DetectionFinding)


def _alert(**kw):
    base = {
        "id": 42, "timestamp": "2026-08-29 10:11:12", "severity": "CRITICAL",
        "status": "OPEN", "threat_type": "MALWARE_C2", "threat_label": "악성코드 C2 통신",
        "src_ip": "203.0.113.5", "dst_ip": "10.0.0.7",
        "description": "C2 비콘 탐지", "confidence": 0.97,
        "verdict": "TRUE_POSITIVE", "verdict_actor": "AI", "origin": "real",
        "details": {"rule_id": "SNORT-2001219"},
    }
    base.update(kw)
    return base


# ─────────────── 독립 검증 ───────────────

def test_output_validates_against_independent_ocsf_model():
    """내가 만든 매핑을 내가 만든 어서션으로 확인하면 그건 검증이 아니다."""
    DetectionFinding(**alert_to_ocsf(_alert()))


@pytest.mark.parametrize("override", [
    {"details": {}},                                  # 룰 ID 없음
    {"src_ip": "myhost", "dst_ip": ""},               # IP 가 아닌 출발지 (실측 26%)
    {"src_ip": None, "dst_ip": None},                 # SIGMA_MATCH 는 None 을 넣는다
    {"severity": "정체불명", "status": "정체불명"},      # 모르는 값
    {"timestamp": "깨진 시각"},
    {"confidence": None},
    {"verdict": None, "origin": None},
    {"details": {"source": "ml", "confidence": 0.4}},  # ML 탐지
])
def test_edge_cases_still_validate(override):
    """현실 데이터는 지저분하다 — 그때도 표준을 벗어나면 안 된다."""
    DetectionFinding(**alert_to_ocsf(_alert(**override)))


def test_real_alert_shapes_validate():
    """실제 저장된 알림으로 검증한다 — 합성 데이터만으로는 놓치는 게 있다."""
    import os

    from modules.alert_store import AlertStore
    if not os.path.exists("data/alerts.db"):
        pytest.skip("실데이터 없음")
    store = AlertStore("data/alerts.db")
    try:
        rows, _total = store.search(limit=300, scope="all")
    finally:
        store.close()
    if not rows:
        pytest.skip("알림이 없음")
    for row in rows:
        DetectionFinding(**alert_to_ocsf(row))


# ─────────────── 스키마 상수 ───────────────

def test_class_and_category_are_detection_finding():
    event = alert_to_ocsf(_alert())
    assert event["class_uid"] == CLASS_UID_DETECTION_FINDING == 2004
    assert event["category_uid"] == CATEGORY_UID_FINDINGS == 2
    assert event["metadata"]["version"] == OCSF_VERSION


def test_type_uid_is_derived_not_hardcoded():
    """type_uid = class_uid * 100 + activity_id — 손으로 적으면 어긋난다."""
    event = alert_to_ocsf(_alert())
    assert event["type_uid"] == event["class_uid"] * 100 + event["activity_id"]


@pytest.mark.parametrize("severity,expected", [
    ("CRITICAL", 5), ("HIGH", 4), ("MEDIUM", 3), ("LOW", 2), ("INFO", 1),
    ("듣도보도못한값", 0),
])
def test_severity_maps_to_ocsf_enum(severity, expected):
    assert alert_to_ocsf(_alert(severity=severity))["severity_id"] == expected


@pytest.mark.parametrize("status,expected", [
    ("OPEN", 1), ("ACK", 2), ("CLOSED", 4), ("듣도보도못한값", 0),
])
def test_status_maps_to_ocsf_enum(status, expected):
    assert alert_to_ocsf(_alert(status=status))["status_id"] == expected


def test_severity_and_status_maps_cover_what_the_system_emits():
    """시스템이 내는 값이 매핑에 없으면 전부 Unknown(0)으로 뭉개진다."""
    from modules.threat_detector import ThreatDetector  # noqa: F401
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert level in SEVERITY_ID
    for state in ("OPEN", "ACK", "CLOSED"):
        assert state in STATUS_ID


@pytest.mark.parametrize("confidence,expected", [
    (0.97, 3), (0.6, 2), (0.2, 1), (97, 3), (60, 2), (None, 0), ("이상한값", 0),
])
def test_confidence_folds_to_three_levels(confidence, expected):
    """0~1 실수와 0~100 정수가 섞여 들어온다 — 둘 다 같은 뜻이어야 한다."""
    assert alert_to_ocsf(_alert(confidence=confidence))["confidence_id"] == expected


# ─────────────── 관측 대상 ───────────────

def test_ip_observable_is_typed_as_ip():
    obs = alert_to_ocsf(_alert())["observables"]
    src = next(o for o in obs if o["name"] == "src_endpoint.ip")
    assert src["type_id"] == 2 and src["value"] == "203.0.113.5"


def test_non_ip_source_is_typed_as_hostname():
    """src_ip 가 항상 IP 인 것은 아니다 — EDR 은 호스트명을 넣는다(실측 26%).

    잘못된 type_id 를 붙이면 받는 쪽에서 조용히 잘못 해석된다.
    """
    obs = alert_to_ocsf(_alert(src_ip="mintkangaroo"))["observables"]
    src = next(o for o in obs if o["name"] == "src_endpoint.hostname")
    assert src["type_id"] == 1


def test_file_and_hash_observables_are_included():
    event = alert_to_ocsf(_alert(details={"path": "/tmp/x.bin", "sha256": "ab" * 32}))
    kinds = {o["name"]: o["type_id"] for o in event["observables"]}
    assert kinds["details.path"] == 7 and kinds["details.sha256"] == 8


def test_empty_observables_are_omitted_not_empty():
    """빈 배열을 실으면 받는 쪽이 '관측 대상이 없다'와 '못 담았다'를 구분 못 한다."""
    event = alert_to_ocsf(_alert(src_ip=None, dst_ip=None, details={}))
    assert "observables" not in event


# ─────────────── 분석 로직(analytic) ───────────────

def test_analytic_falls_back_to_threat_type():
    """룰 ID 가 없다고 비우면 '무엇이 탐지했는지 모르는 알림'이 된다."""
    analytic = alert_to_ocsf(_alert(details={}))["finding_info"]["analytic"]
    assert analytic["uid"] == "MALWARE_C2" and analytic["type_id"] == 1


def test_ml_detection_is_typed_as_learning():
    analytic = alert_to_ocsf(
        _alert(details={"source": "ml"}))["finding_info"]["analytic"]
    assert analytic["type_id"] == 4, "ML 탐지를 Rule 로 표시하면 거짓말이다"


# ─────────────── 손실 방지 ───────────────

def test_analyst_verdict_survives_the_export():
    """정탐/오탐 구분은 이 시스템의 핵심 산출물이다 — 버리면 안 된다."""
    unmapped = alert_to_ocsf(_alert())["unmapped"]
    assert unmapped["verdict"] == "TRUE_POSITIVE"
    assert unmapped["verdict_actor"] == "AI"
    assert unmapped["origin"] == "real"


def test_empty_extension_fields_are_dropped():
    event = alert_to_ocsf(_alert(verdict=None, verdict_actor="", origin=None,
                                 assignee=""))
    assert "verdict" not in event.get("unmapped", {})


def test_time_is_epoch_milliseconds():
    """OCSF `time` 은 밀리초다. 초로 보내면 1970년 근처로 해석된다."""
    event = alert_to_ocsf(_alert(timestamp="2026-08-29 10:11:12"))
    assert event["time"] > 1_700_000_000_000
    assert event["metadata"]["original_time"] == "2026-08-29 10:11:12"


def test_broken_timestamp_still_produces_a_time():
    """시각이 깨졌다고 이벤트를 버리면 그 알림은 밖에서 사라진다."""
    event = alert_to_ocsf(_alert(timestamp="이건 시각이 아니다"))
    assert isinstance(event["time"], int) and event["time"] > 0


def test_batch_export():
    events = alerts_to_ocsf([_alert(id=1), _alert(id=2)])
    assert [e["finding_info"]["uid"] for e in events] == ["1", "2"]
    assert alerts_to_ocsf(None) == []
