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


def get_services():
    app = current_app._get_current_object()
    return (
        app.packet_analyzer,
        app.threat_detector,
        app.sysmon_parser,
        app.hash_checker,
        app.ai_analyst,
        app.ml_analyst,
    )


def _mitre():
    return current_app._get_current_object().mitre_tracker
