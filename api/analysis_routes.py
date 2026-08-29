"""위협 분석: AI · ML · MITRE · 위협 인텔리전스
   (api_bp 공유 — api/routes.py 가 임포트해 라우트를 등록한다)"""
from flask import request, jsonify, current_app
from api._common import (ai_analyst, api_bp, audit_record, ml_analyst, packet_analyzer, threat_detector, _actor, _mitre)


# ------------------------------------------------------------------ #
#  AI 분석
# ------------------------------------------------------------------ #

@api_bp.route("/ai/status", methods=["GET"])
def ai_status():
    ai = ai_analyst()
    return jsonify(ai.get_status())


@api_bp.route("/ai/chat", methods=["POST"])
def ai_chat():
    ai = ai_analyst()
    data    = request.get_json()
    message = data.get("message", "").strip()
    context = data.get("context", {})
    if not message:
        return jsonify({"error": "메시지가 필요합니다"}), 400
    response = ai.chat(message, context)
    return jsonify({"response": response})


@api_bp.route("/ai/analyze/alert/<int:alert_id>", methods=["POST"])
def analyze_alert(alert_id):
    td = threat_detector()
    ai = ai_analyst()
    alerts = td.get_alerts(limit=500)
    target = next((a for a in alerts if a["id"] == alert_id), None)
    if not target:
        return jsonify({"error": "알림을 찾을 수 없습니다"}), 404
    result = ai.analyze_alert(target, async_mode=False)
    return jsonify(result)


@api_bp.route("/ai/analyze/traffic", methods=["POST"])
def analyze_traffic():
    pa = packet_analyzer()
    ai = ai_analyst()
    summary = {
        "stats": pa.get_stats(),
        "top_talkers": pa.get_top_talkers(),
        "protocol_dist": pa.get_protocol_distribution(),
        "traffic_history": pa.get_traffic_history()[-10:],
    }
    result = ai.analyze_packet_summary(summary, async_mode=False)
    return jsonify(result)


@api_bp.route("/ai/history", methods=["GET"])
def ai_history():
    ai = ai_analyst()
    return jsonify({"history": ai.get_history()})


# ------------------------------------------------------------------ #
#  ML 자체 모델 분석
# ------------------------------------------------------------------ #

@api_bp.route("/ml/status", methods=["GET"])
def ml_status():
    ml = ml_analyst()
    return jsonify({
        "stats":  ml.get_stats(),
        "rl":     ml.get_rl_status(),
    })


@api_bp.route("/ml/analyze", methods=["POST"])
def ml_analyze():
    pa = packet_analyzer()
    ml = ml_analyst()
    result = ml.analyze_now(pa.get_stats())
    return jsonify(result)


@api_bp.route("/ml/log", methods=["GET"])
def ml_log():
    ml = ml_analyst()
    limit = int(request.args.get("limit", 20))
    return jsonify({"log": ml.get_log(limit)})


@api_bp.route("/ml/decision", methods=["GET"])
def ml_decision():
    """ML 의사결정 지원 — 유사 위협 그룹핑 + 정오탐 분석 + 대응 권고"""
    ds = current_app._get_current_object().decision_support
    return jsonify(ds.get_summary())


@api_bp.route("/ml/feedback", methods=["POST"])
def ml_feedback():
    ml = ml_analyst()
    data = request.get_json()
    is_fp = data.get("is_false_positive", False)
    ml.mark_alert(is_fp=is_fp)
    return jsonify({"ok": True})


# ------------------------------------------------------------------ #
#  MITRE ATT&CK
# ------------------------------------------------------------------ #

@api_bp.route("/mitre/matrix", methods=["GET"])
def mitre_matrix():
    return jsonify(_mitre().get_matrix())


@api_bp.route("/mitre/recent", methods=["GET"])
def mitre_recent():
    limit = int(request.args.get("limit", 50))
    return jsonify({"events": _mitre().get_recent(limit)})


@api_bp.route("/mitre/top", methods=["GET"])
def mitre_top():
    top = int(request.args.get("top", 10))
    return jsonify({"top": _mitre().get_top_techniques(top)})


@api_bp.route("/mitre/coverage", methods=["GET"])
def mitre_coverage():
    """탐지 커버리지 자가 진단 — 무엇을 탐지하지 *못하는가*.

    히트 0 인 기법이 '공격이 없었다'인지 '룰이 없어 못 본다'인지 구분해 준다.
    """
    from flask import current_app

    from modules.coverage import build_coverage
    app = current_app._get_current_object()
    return jsonify(build_coverage(
        mitre_tracker=getattr(app, "mitre_tracker", None),
        sigma=getattr(app, "sigma", None),
        purple=getattr(app, "purple", None),
        yara=getattr(app, "yara", None),
    ))


@api_bp.route("/mitre/technique/<technique_id>", methods=["GET"])
def mitre_technique_detail(technique_id):
    """특정 Technique의 상세(발생 이력, 관련 알림, 방어권고)를 반환."""
    return jsonify(_mitre().get_technique_detail(technique_id))


# ------------------------------------------------------------------ #
#  위협 인텔리전스 (악성 IP / URL 피드)
# ------------------------------------------------------------------ #

@api_bp.route("/threat-intel/status", methods=["GET"])
def ti_status():
    ti = current_app._get_current_object().threat_intel
    return jsonify(ti.get_status())


@api_bp.route("/threat-intel/refresh", methods=["POST"])
def ti_refresh():
    ti = current_app._get_current_object().threat_intel
    import threading as _t
    _t.Thread(target=ti._refresh_feeds, daemon=True).start()
    return jsonify({"ok": True, "message": "피드 갱신 요청됨"})


# ------------------------------------------------------------------ #
#  IOC 워치리스트 (능동 헌팅)
# ------------------------------------------------------------------ #

@api_bp.route("/watchlist", methods=["GET"])
def watchlist_list():
    wl = current_app._get_current_object().watchlist
    items, stats = wl.list_all()
    return jsonify({"items": items, "stats": stats})


@api_bp.route("/watchlist", methods=["POST"])
def watchlist_add():
    wl = current_app._get_current_object().watchlist
    data = request.get_json() or {}
    res = wl.add(data.get("type"), data.get("value"),
                 note=data.get("note", ""), added_by=_actor())
    if res.get("ok"):
        audit_record("WATCHLIST_ADD",
                     target=f"{data.get('type')}:{data.get('value')}",
                     detail=data.get("note", ""))
        return jsonify({"success": True})
    return jsonify({"success": False, "error": res.get("error")}), 400


@api_bp.route("/watchlist/<int:ioc_id>", methods=["DELETE"])
def watchlist_remove(ioc_id):
    wl = current_app._get_current_object().watchlist
    value = wl.get(ioc_id)
    ok = wl.remove(ioc_id)
    if ok:
        audit_record("WATCHLIST_REMOVE", target=value or f"#{ioc_id}")
    return jsonify({"success": ok})


@api_bp.route("/watchlist/check", methods=["POST"])
def watchlist_check():
    wl = current_app._get_current_object().watchlist
    value = (request.get_json() or {}).get("value", "").strip()
    return jsonify({"value": value, "type": wl.match(value)})


# ------------------------------------------------------------------ #
#  킬체인 상관관계 (공격 캠페인)
# ------------------------------------------------------------------ #

@api_bp.route("/correlation/campaigns", methods=["GET"])
def correlation_campaigns():
    """같은 출발지 알림을 시간 윈도우로 묶어 MITRE 킬체인 캠페인으로 구성."""
    from modules import correlation
    app = current_app._get_current_object()
    store = getattr(app.threat_detector, "store", None)
    hours = min(168, max(1, request.args.get("hours", 24, type=int)))
    window = min(240, max(1, request.args.get("window", 30, type=int)))
    labels = app.threat_detector.threat_type_labels()
    return jsonify(correlation.compute(store, hours=hours,
                                       window_minutes=window, min_alerts=2,
                                       labels=labels))


# ------------------------------------------------------------------ #
#  위협 헌팅 콘솔 (docs/AUDIT.md 3단계 제안 #7)
# ------------------------------------------------------------------ #

def _hunts():
    return getattr(current_app._get_current_object(), "hunts", None)


@api_bp.route("/hunts", methods=["GET"])
def hunts_list():
    store = _hunts()
    if store is None:
        return jsonify({"hunts": [], "enabled": False})
    return jsonify({"hunts": store.list_all(), "enabled": True})


@api_bp.route("/hunts", methods=["POST"])
def hunts_create():
    store = _hunts()
    if store is None:
        return jsonify({"error": "헌팅 저장소가 비활성입니다"}), 503
    body = request.get_json(silent=True) or {}
    try:
        created = store.create(body.get("name", ""), body.get("filters") or {},
                               description=body.get("description", ""),
                               created_by=_actor())
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    audit_record("HUNT_CREATE", created["name"], str(created["filters"]))
    return jsonify(created), 201


@api_bp.route("/hunts/<int:hunt_id>", methods=["PUT"])
def hunts_update(hunt_id):
    store = _hunts()
    if store is None:
        return jsonify({"error": "헌팅 저장소가 비활성입니다"}), 503
    body = request.get_json(silent=True) or {}
    ok = store.update(hunt_id, name=body.get("name"), filters=body.get("filters"),
                      description=body.get("description"))
    if not ok:
        return jsonify({"error": "헌팅을 찾을 수 없거나 바뀐 내용이 없습니다"}), 404
    audit_record("HUNT_UPDATE", str(hunt_id))
    return jsonify(store.get(hunt_id))


@api_bp.route("/hunts/<int:hunt_id>", methods=["DELETE"])
def hunts_delete(hunt_id):
    store = _hunts()
    if store is None:
        return jsonify({"error": "헌팅 저장소가 비활성입니다"}), 503
    if not store.delete(hunt_id):
        return jsonify({"error": "헌팅을 찾을 수 없습니다"}), 404
    audit_record("HUNT_DELETE", str(hunt_id))
    return jsonify({"deleted": hunt_id})


@api_bp.route("/hunts/<int:hunt_id>/run", methods=["GET"])
def hunts_run(hunt_id):
    """헌팅 실행 — 조회 전용이라 GET 이다.

    `mark=0` 이면 '지난 실행 이후' 기준선을 갱신하지 않는다. 미리보기로 돌려볼
    때 델타가 소진되면 안 되기 때문이다.
    """
    store = _hunts()
    if store is None:
        return jsonify({"error": "헌팅 저장소가 비활성입니다"}), 503
    limit = min(500, max(1, request.args.get("limit", 100, type=int)))
    mark = (request.args.get("mark", "1") or "1").lower() not in ("0", "false", "no")
    result = store.run(hunt_id, limit=limit, mark=mark)
    if result is None:
        return jsonify({"error": "헌팅을 찾을 수 없습니다"}), 404
    return jsonify(result)


@api_bp.route("/hunts/promote", methods=["POST"])
def hunts_promote():
    """헌팅에서 찾은 지표를 워치리스트로 승격한다.

    결과가 행동으로 이어지지 않으면 헌팅은 조회일 뿐이다.
    """
    store = _hunts()
    if store is None:
        return jsonify({"error": "헌팅 저장소가 비활성입니다"}), 503
    body = request.get_json(silent=True) or {}
    value = (body.get("value") or "").strip()
    if not value:
        return jsonify({"error": "승격할 지표(value)가 필요합니다"}), 400
    result = store.promote_to_watchlist(value, ioc_type=body.get("type", "ip"),
                                        note=body.get("note", ""), actor=_actor())
    if not result.get("ok"):
        return jsonify(result), 400
    audit_record("WATCHLIST_ADD", value, "헌팅에서 승격")
    return jsonify(result)
