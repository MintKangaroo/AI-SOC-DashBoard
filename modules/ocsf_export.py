"""OCSF 내보내기 (docs/AUDIT.md 3단계 제안 #1).

감사는 **OCSF 전면 도입을 비추천**했다. 이유가 셋이었다 — 모듈 간 포맷은
`threat_detector.report_alert()` 단일 진입점으로 이미 통일돼 있고, 40개 모듈의
이벤트를 OCSF 클래스에 매핑하는 건 작업량 L 인데 얻는 게 "표준을 따른다"는
사실뿐이며, 화면에 아무 변화가 없다.

대신 권고된 것이 **내보내기 계층 하나**다. 내부 구조는 그대로 두고 밖으로
나갈 때만 표준 형태로 바꾼다. 그러면 상호운용성은 얻고 대공사는 피한다.

**스키마를 기억으로 쓰지 않았다.** 아래 상수는 전부 schema.ocsf.io 의 1.1.0
정의에서 확인한 값이다(Detection Finding = class_uid 2004, category 2).

**과장하지 않는다**: 이건 OCSF **핵심 필드 부분집합**이다. 인증받은 완전
매핑이 아니다. `cloud`·`action_id` 같은 필드는 각각 cloud·security_control
프로필이 적용될 때만 필수인데, 이 대시보드는 온프렘이라 그 프로필을 쓰지
않으므로 선언하지 않는다. 선언하지 않은 프로필의 필드를 채우는 척하는 것이
빈칸으로 두는 것보다 나쁘다.
"""
from datetime import datetime

# ── schema.ocsf.io/1.1.0 에서 확인한 값 ──
OCSF_VERSION = "1.1.0"
CLASS_UID_DETECTION_FINDING = 2004
CATEGORY_UID_FINDINGS = 2
ACTIVITY_CREATE = 1              # activity_id: 0 Unknown / 1 Create / 2 Update / 3 Close

# severity_id: 0 Unknown / 1 Informational / 2 Low / 3 Medium / 4 High / 5 Critical / 6 Fatal
SEVERITY_ID = {
    "INFO": 1, "INFORMATIONAL": 1,
    "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5,
}
# status_id: 0 Unknown / 1 New / 2 In Progress / 3 Suppressed / 4 Resolved
STATUS_ID = {"OPEN": 1, "ACK": 2, "CLOSED": 4, "SUPPRESSED": 3}
# confidence_id: 0 Unknown / 1 Low / 2 Medium / 3 High
CONFIDENCE_ID = {"low": 1, "medium": 2, "high": 3}

# observable type_id (요약): 1 Hostname / 2 IP Address / 7 File Name / 8 Hash / 10 Resource UID
OBSERVABLE_HOSTNAME = 1
OBSERVABLE_IP = 2
OBSERVABLE_FILE_NAME = 7
OBSERVABLE_HASH = 8

PRODUCT = {"name": "SOC Dashboard", "vendor_name": "MintKangaroo",
           "version": "1.0", "feature": {"name": "Detection Pipeline"}}


def _epoch_ms(timestamp):
    """'YYYY-MM-DD HH:MM:SS' → epoch milliseconds. OCSF `time` 은 ms 다."""
    if not timestamp:
        return None
    try:
        return int(datetime.strptime(str(timestamp), "%Y-%m-%d %H:%M:%S").timestamp() * 1000)
    except ValueError:
        return None


def _looks_like_ip(value):
    parts = str(value or "").split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _confidence_id(confidence):
    """0~1 실수 또는 0~100 정수를 OCSF 3단계로 접는다."""
    if confidence in (None, ""):
        return 0
    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return 0
    pct = value * 100 if value <= 1 else value
    if pct >= 80:
        return CONFIDENCE_ID["high"]
    if pct >= 50:
        return CONFIDENCE_ID["medium"]
    return CONFIDENCE_ID["low"]


# analytic.type_id: 0 Unknown / 1 Rule / 2 Behavioral / 3 Statistical / 4 Learning(ML/DL)
ANALYTIC_RULE = 1
ANALYTIC_LEARNING = 4
_ML_SOURCES = {"ml", "ml_analyst", "anomaly", "isolation_forest"}


def _analytic(alert, details):
    """탐지 로직의 정체. 무엇이 이 알림을 만들었는가.

    스키마상 필수는 `type_id` 뿐이고 `uid`·`name` 은 권장이다. 그런데 룰 ID 가
    없다고 uid 를 빼면 '무엇이 탐지했는지 모르는 알림'이 된다 — 이 시스템에서
    룰 ID 가 없는 탐지는 threat_type 자체가 룰의 정체이므로 그것을 쓴다.
    (참고: py-ocsf-models 는 uid 를 필수로 강제한다. 스펙보다 엄격하지만
     어차피 채우는 편이 맞다.)
    """
    rule_id = details.get("rule_id") or details.get("sid") or details.get("signature_id")
    identity = str(rule_id or alert.get("threat_type") or "detector")
    source = str(details.get("source") or "").lower()
    type_id = ANALYTIC_LEARNING if source in _ML_SOURCES else ANALYTIC_RULE
    return {"name": identity, "type_id": type_id, "uid": identity}


def _observables(alert):
    """출발지/목적지를 관측 대상으로 싣는다.

    src_ip 가 항상 IP 인 것은 아니다 — EDR 은 호스트명을, SIGMA_MATCH 는 None 을
    넣는다(실측 26%). 값을 보고 종류를 정한다. 잘못된 type_id 를 붙이면 받는
    쪽에서 조용히 잘못 해석된다.
    """
    out = []
    for name, value in (("src_endpoint.ip", alert.get("src_ip")),
                        ("dst_endpoint.ip", alert.get("dst_ip"))):
        value = (value or "").strip() if isinstance(value, str) else value
        if not value:
            continue
        if _looks_like_ip(value):
            out.append({"name": name, "type_id": OBSERVABLE_IP, "value": str(value)})
        else:
            out.append({"name": name.replace(".ip", ".hostname"),
                        "type_id": OBSERVABLE_HOSTNAME, "value": str(value)})
    details = alert.get("details") or {}
    for key, type_id in (("path", OBSERVABLE_FILE_NAME), ("sha256", OBSERVABLE_HASH),
                         ("md5", OBSERVABLE_HASH)):
        if details.get(key):
            out.append({"name": f"details.{key}", "type_id": type_id,
                        "value": str(details[key])})
    return out


def alert_to_ocsf(alert):
    """알림 1건 → OCSF Detection Finding (class_uid 2004)."""
    details = alert.get("details") or {}
    severity = str(alert.get("severity") or "").upper()
    timestamp = _epoch_ms(alert.get("timestamp"))
    finding_id = str(alert.get("id"))

    event = {
        # ── 필수 (프로필 없음 기준) ──
        "activity_id": ACTIVITY_CREATE,
        "category_uid": CATEGORY_UID_FINDINGS,
        "class_uid": CLASS_UID_DETECTION_FINDING,
        "type_uid": CLASS_UID_DETECTION_FINDING * 100 + ACTIVITY_CREATE,
        "severity_id": SEVERITY_ID.get(severity, 0),
        "time": timestamp if timestamp is not None else int(datetime.now().timestamp() * 1000),
        "metadata": {
            "version": OCSF_VERSION,
            "product": dict(PRODUCT),
            "original_time": alert.get("timestamp"),
            "logged_time": _epoch_ms(alert.get("timestamp")),
        },
        "finding_info": {
            "uid": finding_id,
            "title": alert.get("threat_label") or alert.get("threat_type") or "Security Finding",
            "desc": alert.get("description") or "",
            "types": [t for t in [alert.get("threat_type")] if t],
            "analytic": _analytic(alert, details),
        },
        # ── 권장 ──
        "message": alert.get("description") or "",
        "severity": severity or "Unknown",
        "status_id": STATUS_ID.get(str(alert.get("status") or "").upper(), 0),
        "status": alert.get("status") or "Unknown",
        "confidence_id": _confidence_id(alert.get("confidence")
                                        or details.get("confidence")),
        "count": int(details.get("dedup", {}).get("count", 1)
                     if isinstance(details.get("dedup"), dict) else 1),
        "observables": _observables(alert),
        # ── 확장: 표준에 없지만 버리면 정보가 사라지는 것들 ──
        # OCSF 는 벤더 확장을 허용한다. 분석가 판정·출처는 이 시스템의 핵심
        # 산출물이라(정탐/오탐 구분이 이 프로젝트의 주제다) 접두를 붙여 싣는다.
        "unmapped": {
            "verdict": alert.get("verdict"),
            "verdict_actor": alert.get("verdict_actor"),
            "verdict_reason": alert.get("verdict_reason"),
            "origin": alert.get("origin"),
            "assignee": alert.get("assignee"),
            "archived": alert.get("archived"),
        },
    }
    # 빈 값은 싣지 않는다 — 받는 쪽이 '값이 있는데 비었다'로 오해한다
    event["unmapped"] = {k: v for k, v in event["unmapped"].items()
                         if v not in (None, "", [])}
    if not event["observables"]:
        del event["observables"]
    return event


def alerts_to_ocsf(alerts):
    return [alert_to_ocsf(a) for a in alerts or []]
