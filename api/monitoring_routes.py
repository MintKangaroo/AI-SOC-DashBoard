"""모니터링: 내정보/헬스 · SIEM · IP평판 · EDR · 네트워크
   (api_bp 공유 — api/routes.py 가 임포트해 라우트를 등록한다)"""
import re

from flask import request, jsonify, current_app
from api._common import (api_bp, audit_record, _actor)


# ------------------------------------------------------------------ #
#  내 정보 (시스템/네트워크)
# ------------------------------------------------------------------ #

@api_bp.route("/system/info", methods=["GET"])
def system_info():
    from modules import system_info as _si
    return jsonify(_si.get_all())


@api_bp.route("/metrics/soc", methods=["GET"])
def metrics_soc():
    """SOC 운영 지표 — 알림 시계열 + 인시던트 MTTR/MTTA."""
    from modules import soc_metrics
    app = current_app._get_current_object()
    days = min(90, max(1, request.args.get("days", 14, type=int)))
    store = getattr(app.threat_detector, "store", None)
    incidents = getattr(app.incidents, "incidents", {})
    soar_stats = (app.soar.get_status() or {}).get("stats") if hasattr(app, "soar") else None
    dedup = getattr(app, "alert_dedup", None)
    dedup_stats = dedup.get_stats() if dedup is not None else None
    out = soc_metrics.compute(store, incidents, soar_stats, days=days,
                              dedup_stats=dedup_stats)
    out["labels"] = app.threat_detector.threat_type_labels()
    return jsonify(out)


@api_bp.route("/audit", methods=["GET"])
def audit_search():
    """전역 감사 로그 검색 (분석가 조치 이력)."""
    app = current_app._get_current_object()
    audit = getattr(app, "audit", None)
    if audit is None:
        return jsonify({"events": [], "total": 0, "page": 1, "pages": 0, "labels": {}})
    a = request.args
    page  = max(1, a.get("page", 1, type=int))
    limit = min(200, max(1, a.get("limit", 50, type=int)))
    rows, total = audit.search(
        action=a.get("action") or None,
        actor=(a.get("actor") or "").strip() or None,
        text=(a.get("text") or "").strip() or None,
        date_from=a.get("from") or None,
        date_to=a.get("to") or None,
        limit=limit, offset=(page - 1) * limit)
    return jsonify({"events": rows, "total": total, "page": page, "limit": limit,
                    "pages": (total + limit - 1) // limit, "labels": audit.labels()})


@api_bp.route("/system/health", methods=["GET"])
def system_health():
    """전 모듈 가동 상태·동작 모드(실측/데모/비활성) 집계."""
    from modules import system_health as _sh
    return jsonify(_sh.collect(current_app._get_current_object()))


@api_bp.route("/system/public-ip", methods=["GET"])
def system_public_ip():
    from modules import system_info as _si
    force = request.args.get("force") in ("1", "true", "yes")
    ip = _si.get_public_ip(force=force)
    geo = _si.get_geo_info(ip) if ip else None
    return jsonify({"public_ip": ip, "geo": geo})


@api_bp.route("/threat-intel/check", methods=["POST"])
def ti_check():
    ti = current_app._get_current_object().threat_intel
    data = request.get_json() or {}
    ip = data.get("ip")
    url = data.get("url")
    return jsonify({
        "ip":  ip,  "ip_malicious":  ti.check_ip(ip) if ip else None,
        "url": url, "url_malicious": ti.check_url(url) if url else None,
    })


# ------------------------------------------------------------------ #
#  외부 시스템 연동 — SIEM (접근 로그 수집)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/siem", methods=["GET"])
def siem_status():
    siem = current_app._get_current_object().siem_collector
    return jsonify(siem.get_status())


@api_bp.route("/integrations/siem/events", methods=["GET"])
def siem_events():
    siem = current_app._get_current_object().siem_collector
    limit = int(request.args.get("limit", 100))
    source = request.args.get("source")
    suspicious = request.args.get("suspicious") in ("1", "true", "yes")
    return jsonify({"events": siem.get_events(limit=limit, source=source,
                                              suspicious_only=suspicious)})


@api_bp.route("/authlog", methods=["GET"])
def authlog_status():
    return jsonify(current_app._get_current_object().authlog.get_status())


# ------------------------------------------------------------------ #
#  Syslog 수신 (원격 침해시도 수집)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/syslog", methods=["GET"])
def syslog_status():
    recv = getattr(current_app._get_current_object(), "syslog_receiver", None)
    if recv is None:
        return jsonify({"stats": {}, "config": {}, "events": []})
    return jsonify(recv.get_status())


@api_bp.route("/integrations/syslog/events", methods=["GET"])
def syslog_events():
    recv = current_app._get_current_object().syslog_receiver
    limit = int(request.args.get("limit", 100))
    source = request.args.get("source")
    suspicious = request.args.get("suspicious") in ("1", "true", "yes")
    return jsonify({"events": recv.get_events(limit=limit, source=source,
                                              suspicious_only=suspicious)})


# ------------------------------------------------------------------ #
#  허니팟 (유인 서비스)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/honeypot", methods=["GET"])
def honeypot_status():
    hp = getattr(current_app._get_current_object(), "honeypot", None)
    if hp is None:
        return jsonify({"stats": {}, "config": {}, "events": []})
    return jsonify(hp.get_status())


@api_bp.route("/integrations/snort", methods=["GET"])
def snort_status():
    sensor = getattr(current_app._get_current_object(), "snort", None)
    if sensor is None:
        return jsonify({"enabled": False, "status": "unavailable", "recent": []})
    return jsonify(sensor.get_status())


# ------------------------------------------------------------------ #
#  SIEM 상관관계 분석
# ------------------------------------------------------------------ #

@api_bp.route("/siem/correlation", methods=["GET"])
def siem_correlation_status():
    sc = getattr(current_app._get_current_object(), "siem_correlator", None)
    if sc is None:
        return jsonify({"stats": {}, "rules": [], "findings": []})
    return jsonify(sc.get_status())


# ------------------------------------------------------------------ #
#  IP 평판 조회 (AbuseIPDB)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/abuseipdb", methods=["GET"])
def ip_reputation_status():
    return jsonify(current_app._get_current_object().ip_reputation.get_status())


@api_bp.route("/reputation/check", methods=["POST"])
def ip_reputation_check():
    rep = current_app._get_current_object().ip_reputation
    ip = (request.get_json() or {}).get("ip")
    if not ip:
        return jsonify({"error": "ip 필요"}), 400
    return jsonify(rep.check(ip, force=True))


# ------------------------------------------------------------------ #
#  EDR (엔드포인트 탐지·대응)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/edr", methods=["GET"])
def edr_status():
    return jsonify(current_app._get_current_object().edr.get_status())


@api_bp.route("/edr/kill", methods=["POST"])
def edr_kill():
    edr = current_app._get_current_object().edr
    pid = (request.get_json() or {}).get("pid")
    if pid is None:
        return jsonify({"error": "pid 필요"}), 400
    ok, detail = edr.kill_process(pid, reason="분석가 수동 격리")
    return jsonify({"ok": ok, "detail": detail})


# ------------------------------------------------------------------ #
#  네트워크 모니터링 관제
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/network", methods=["GET"])
def network_status():
    return jsonify(current_app._get_current_object().net_monitor.get_status())


# ------------------------------------------------------------------ #
#  알림 중복제거 · 억제 (modules/alert_dedup.py)
# ------------------------------------------------------------------ #

def _dedup():
    layer = getattr(current_app._get_current_object(), "alert_dedup", None)
    if layer is None:
        raise LookupError("중복제거 레이어가 설정되지 않았습니다")
    return layer


@api_bp.route("/dedup/status", methods=["GET"])
def dedup_status():
    """중복제거·억제 현황 + 등록된 규칙."""
    try:
        layer = _dedup()
    except LookupError as e:
        return jsonify({"enabled": False, "error": str(e)}), 200
    return jsonify({"stats": layer.get_stats(), "rules": layer.get_rules()})


@api_bp.route("/dedup/suppressed", methods=["GET"])
def dedup_suppressed():
    """억제·병합된 이벤트 조회 — 잘못 억제한 것을 되짚는 경로."""
    try:
        layer = _dedup()
    except LookupError as e:
        return jsonify({"error": str(e)}), 503
    a = request.args
    page = max(1, a.get("page", 1, type=int))
    limit = min(200, max(1, a.get("limit", 50, type=int)))
    rows, total = layer.suppressed(
        limit=limit, offset=(page - 1) * limit,
        kind=a.get("kind") or None,
        fingerprint_value=a.get("fingerprint") or None,
        parent_alert=a.get("parent_alert", type=int),
    )
    return jsonify({"events": rows, "total": total, "page": page, "limit": limit,
                    "pages": max(1, (total + limit - 1) // limit)})


@api_bp.route("/dedup/rules", methods=["POST"])
def dedup_add_rule():
    """억제 규칙 등록. CRITICAL 은 규칙으로 억제되지 않는다."""
    try:
        layer = _dedup()
    except LookupError as e:
        return jsonify({"error": str(e)}), 503
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "규칙 이름이 필요합니다"}), 400
    if not any(data.get(k) for k in ("threat_type", "src_prefix", "rule_id", "desc_regex")):
        return jsonify({"error": "조건을 최소 하나는 지정하세요 "
                                 "(threat_type/src_prefix/rule_id/desc_regex)"}), 400
    try:
        rule_id = layer.add_rule(
            name=name,
            threat_type=(data.get("threat_type") or "").strip(),
            src_prefix=(data.get("src_prefix") or "").strip(),
            rule_id=(data.get("rule_id") or "").strip(),
            desc_regex=(data.get("desc_regex") or "").strip(),
            reason=(data.get("reason") or "").strip(),
        )
    except re.error as e:
        return jsonify({"error": f"정규식 오류: {e}"}), 400
    audit_record("DEDUP_RULE_ADD", target=name, detail=data.get("reason", ""))
    return jsonify({"ok": True, "id": rule_id})


@api_bp.route("/dedup/rules/<int:rule_id>", methods=["DELETE"])
def dedup_delete_rule(rule_id):
    try:
        layer = _dedup()
    except LookupError as e:
        return jsonify({"error": str(e)}), 503
    layer.delete_rule(rule_id)
    audit_record("DEDUP_RULE_DELETE", target=str(rule_id))
    return jsonify({"ok": True})


@api_bp.route("/dedup/rules/<int:rule_id>/toggle", methods=["POST"])
def dedup_toggle_rule(rule_id):
    try:
        layer = _dedup()
    except LookupError as e:
        return jsonify({"error": str(e)}), 503
    enabled = bool((request.get_json() or {}).get("enabled", True))
    layer.set_rule_enabled(rule_id, enabled)
    audit_record("DEDUP_RULE_TOGGLE", target=str(rule_id),
                 detail=f"{_actor()} → {'활성' if enabled else '비활성'}")
    return jsonify({"ok": True, "enabled": enabled})
