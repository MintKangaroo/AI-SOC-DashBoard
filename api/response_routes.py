"""대응: SOAR · 인시던트 · 대시보드 요약
   (api_bp 공유 — api/routes.py 가 임포트해 라우트를 등록한다)"""
from flask import request, jsonify, current_app
from api._common import (ai_analyst, api_bp, audit_record, ml_analyst, packet_analyzer, sysmon_parser, threat_detector, _actor, _mitre)


# ------------------------------------------------------------------ #
#  SOAR 자동 대응
# ------------------------------------------------------------------ #

def _soar():
    return current_app._get_current_object().soar


@api_bp.route("/soar/status", methods=["GET"])
def soar_status():
    return jsonify(_soar().get_status())


@api_bp.route("/soar/playbooks/<pb_id>/toggle", methods=["POST"])
def soar_toggle_playbook(pb_id):
    enabled = _soar().toggle_playbook(pb_id)
    if enabled is None:
        return jsonify({"error": "플레이북 없음"}), 404
    return jsonify({"id": pb_id, "enabled": enabled})


@api_bp.route("/soar/virustotal/test", methods=["POST"])
def soar_virustotal_test():
    data = request.get_json(silent=True) or {}
    value = (data.get("hash") or "").strip()
    if not value:
        return jsonify({"error": "hash가 필요합니다"}), 400
    result = _soar().test_virustotal(value)
    audit_record("VIRUSTOTAL_TEST", target=value[:16] + "…",
                 detail=f"{result.get('status')} / {result.get('verdict', 'UNKNOWN')}")
    return jsonify(result), (200 if result.get("ok") else 400)


@api_bp.route("/soar/executions/<int:execution_id>/retry", methods=["POST"])
def soar_retry_execution(execution_id):
    result = _soar().retry_execution(execution_id)
    if result.get("ok"):
        audit_record("SOAR_RETRY", target=f"실행 #{execution_id}",
                     detail=f"새 실행 #{result.get('execution_id')}")
        return jsonify(result)
    codes = {"not_found": 404, "not_failed": 409, "not_retryable": 409}
    return jsonify(result), codes.get(result.get("status"), 400)


@api_bp.route("/soar/block", methods=["POST"])
def soar_block():
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip 가 필요합니다"}), 400
    reason = data.get("reason", "분석가 수동 차단")
    result = _soar().manual_block_request(ip, reason)
    if result["success"]:
        action = "SOAR_APPROVAL_REQUEST" if result["status"] == "waiting_approval" else "SOAR_BLOCK"
        audit_record(action, target=ip, detail=reason)
    result["message"] = ("승인 대기" if result["status"] == "waiting_approval" else
                         "차단됨" if result["success"] else "차단 요청 거부")
    return jsonify(result)


@api_bp.route("/soar/executions/<int:execution_id>/approval", methods=["POST"])
def soar_review_approval(execution_id):
    data = request.get_json(silent=True) or {}
    decision = data.get("decision")
    reason = (data.get("reason") or "").strip()
    result = _soar().review_approval(execution_id, decision, _actor(), reason)
    if result.get("ok"):
        audit_record(f"SOAR_{decision.upper()}", target=f"실행 #{execution_id}", detail=reason)
        return jsonify(result)
    codes = {"not_found": 404, "not_pending": 409, "invalid_decision": 400}
    return jsonify(result), codes.get(result.get("status"), 400)


@api_bp.route("/soar/approvals/batch", methods=["POST"])
def soar_batch_approval():
    data = request.get_json(silent=True) or {}
    execution_ids = data.get("execution_ids")
    if not isinstance(execution_ids, list) or not execution_ids:
        return jsonify({"error": "execution_ids 목록이 필요합니다"}), 400
    reason = (data.get("reason") or "일괄 승인").strip()[:300]
    result = _soar().approve_many(execution_ids, _actor(), reason)
    audit_record("SOAR_BATCH_APPROVE", target=f"{result['requested']}건",
                 detail=f"승인 {result['approved']} · 실패 {result['failed']} · {reason}")
    return jsonify(result), (200 if result["ok"] else 409)


@api_bp.route("/soar/unblock", methods=["POST"])
def soar_unblock():
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip 가 필요합니다"}), 400
    ok = _soar().manual_unblock(ip)
    if ok:
        audit_record("SOAR_UNBLOCK", target=ip)
    return jsonify({"success": ok})


# ------------------------------------------------------------------ #
#  인시던트 (케이스) 관리
# ------------------------------------------------------------------ #

def _incidents():
    return current_app._get_current_object().incidents


@api_bp.route("/incidents", methods=["GET"])
def incidents_list():
    status = request.args.get("status")
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "stats": _incidents().get_stats(),
        "incidents": _incidents().get_all(limit=limit, status=status),
    })


@api_bp.route("/incidents/<int:inc_id>", methods=["GET"])
def incident_detail(inc_id):
    inc = _incidents().get(inc_id)
    if not inc:
        return jsonify({"error": "인시던트 없음"}), 404
    return jsonify(inc)


@api_bp.route("/incidents/<int:inc_id>", methods=["PUT"])
def incident_update(inc_id):
    data = request.get_json() or {}
    status = data.get("status")
    if status and status not in ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"):
        return jsonify({"error": "유효하지 않은 상태"}), 400
    ok = _incidents().update(inc_id, status=status,
                             assignee=data.get("assignee"),
                             note=data.get("note"))
    if ok:
        if status:
            audit_record("INCIDENT_STATUS", target=f"인시던트 #{inc_id}", detail=status)
        if data.get("assignee") is not None:
            audit_record("INCIDENT_ASSIGN", target=f"인시던트 #{inc_id}",
                         detail=data.get("assignee") or "(해제)")
        if data.get("note"):
            audit_record("INCIDENT_NOTE", target=f"인시던트 #{inc_id}", detail=data.get("note"))
    return jsonify({"success": ok})


# ------------------------------------------------------------------ #
#  통합 대시보드 요약
# ------------------------------------------------------------------ #

@api_bp.route("/dashboard/summary", methods=["GET"])
def dashboard_summary():
    pa = packet_analyzer()
    td = threat_detector()
    sp = sysmon_parser()
    ai = ai_analyst()
    ml = ml_analyst()
    mitre = _mitre()
    matrix = mitre.get_matrix()
    return jsonify({
        "packets":  pa.get_stats(),
        "threats":  td.get_stats(),
        "sysmon":   sp.get_stats(),
        "ai":       ai.get_status(),
        "ml":       ml.get_stats(),
        "mitre":    {"total_mapped": matrix["total_mapped"],
                     "unique_techniques": matrix["unique_techniques"]},
        "timestamp": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
