import os

from flask import Blueprint, current_app, session

api_bp = Blueprint("api", __name__)


def _actor():
    """조치 주체(로그인 사용자). 감사 로그·워치리스트 기록용."""
    return session.get("user") or "system"


def audit_record(action, target="", detail=""):
    """전역 감사 로그에 분석가 조치 1건 기록 (app.audit 없으면 무시)."""
    audit = getattr(current_app._get_current_object(), "audit", None)
    if audit:
        audit.record(_actor(), action, target, detail)


def _hash_scan_allowed(path):
    """해시 스캔 허용 디렉터리 검사 (경로 탈출 방지)"""
    allowed = os.getenv("HASH_SCAN_ALLOWED_DIRS")
    if allowed:
        dirs = [d.strip() for d in allowed.split(",") if d.strip()]
    else:
        dirs = [os.path.expanduser("~"), os.getcwd()]
    real = os.path.realpath(path)
    for d in dirs:
        base = os.path.realpath(d)
        if real == base or real.startswith(base + os.sep):
            return True
    return False


# 서비스 접근자 (docs/AUDIT.md A-6)
#
# 예전에는 `get_services()` 가 6-튜플을 돌려주고 호출부가 위치로 언패킹했다
# (`_, _, _, hc, _, _ = get_services()`). 튜플 순서를 한 칸만 바꿔도 조용히
# 잘못된 서비스가 바인딩되고, 읽는 쪽에서는 몇 번째가 무엇인지 셀 수가 없다.
# 이름으로 꺼내면 순서 자체가 사라진다.

def _service(name):
    return getattr(current_app._get_current_object(), name)


def packet_analyzer():
    return _service("packet_analyzer")


def threat_detector():
    return _service("threat_detector")


def sysmon_parser():
    return _service("sysmon_parser")


def hash_checker():
    return _service("hash_checker")


def ai_analyst():
    return _service("ai_analyst")


def ml_analyst():
    return _service("ml_analyst")


def _mitre():
    return current_app._get_current_object().mitre_tracker
