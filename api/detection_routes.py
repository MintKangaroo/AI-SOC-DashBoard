"""탐지·수집: 패킷 · 위협알림(이력/CSV) · Sysmon · 해시
   (api_bp 공유 — api/routes.py 가 임포트해 라우트를 등록한다)"""
from flask import request, jsonify, current_app
from api._common import (api_bp, audit_record, hash_checker, packet_analyzer, sysmon_parser, threat_detector, _hash_scan_allowed)


# ------------------------------------------------------------------ #
#  패킷 분석
# ------------------------------------------------------------------ #

@api_bp.route("/packets", methods=["GET"])
def get_packets():
    pa = packet_analyzer()
    limit = int(request.args.get("limit", 50))
    return jsonify({"packets": pa.get_recent_packets(limit), "stats": pa.get_stats()})


@api_bp.route("/packets/stats", methods=["GET"])
def packet_stats():
    pa = packet_analyzer()
    return jsonify({
        "stats": pa.get_stats(),
        "top_talkers": pa.get_top_talkers(),
        "protocol_dist": pa.get_protocol_distribution(),
        "traffic_history": pa.get_traffic_history(),
    })


# ------------------------------------------------------------------ #
#  위협 탐지
# ------------------------------------------------------------------ #

@api_bp.route("/alerts", methods=["GET"])
def get_alerts():
    td = threat_detector()
    limit    = int(request.args.get("limit", 100))
    severity = request.args.get("severity")
    status   = request.args.get("status")
    return jsonify({
        "alerts": td.get_alerts(limit=limit, severity=severity, status=status),
        "stats":  td.get_stats(),
    })


@api_bp.route("/alerts/groups", methods=["GET"])
def alert_groups():
    """반복 알림을 출발지 IP·위협유형으로 묶어 조사 우선순위로 제공한다."""
    td = threat_detector()
    hours = min(24 * 30, max(1, request.args.get("hours", 24, type=int)))
    limit = min(100, max(1, request.args.get("limit", 20, type=int)))
    min_count = min(100, max(2, request.args.get("min_count", 2, type=int)))
    if td.store:
        groups = td.store.grouped_recent(hours=hours, min_count=min_count, limit=limit)
    else:
        grouped = {}
        for alert in td.get_alerts(limit=500):
            key = (alert.get("src_ip"), alert.get("threat_type"))
            item = grouped.setdefault(key, {"src_ip": key[0], "threat_type": key[1],
                "count": 0, "open_count": 0, "severity": alert.get("severity"),
                "first_seen": alert.get("timestamp"), "last_seen": alert.get("timestamp")})
            item["count"] += 1
            item["open_count"] += alert.get("status") == "OPEN"
            item["last_seen"] = max(item["last_seen"], alert.get("timestamp"))
        groups = sorted((g for g in grouped.values() if g["count"] >= min_count),
                        key=lambda g: (g["open_count"], g["count"]), reverse=True)[:limit]
    for group in groups:
        group["threat_label"] = td.threat_type_labels().get(
            group["threat_type"], group["threat_type"])
    return jsonify({"hours": hours, "groups": groups, "total": len(groups)})


@api_bp.route("/alerts/history", methods=["GET"])
def alerts_history():
    """전체 알림 이력 검색 (기간·심각도·상태·유형·IP·본문). 페이지네이션.

    scope: all(활성+아카이브, 기본) / live(활성만) / archive(아카이브만).
    """
    td = threat_detector()
    a = request.args
    page  = max(1, a.get("page", 1, type=int))
    limit = min(200, max(1, a.get("limit", 50, type=int)))
    scope = a.get("scope") or "all"
    if scope not in ("all", "live", "archive"):
        return jsonify({"error": "scope 는 all/live/archive 중 하나여야 합니다"}), 400
    rows, total = td.search_alerts(
        scope=scope,
        severity=a.get("severity") or None,
        status=a.get("status") or None,
        threat_type=a.get("threat_type") or None,
        verdict=a.get("verdict") or None,
        origin=a.get("origin") or None,
        ip=(a.get("ip") or "").strip() or None,
        text=(a.get("text") or "").strip() or None,
        date_from=a.get("from") or None,
        date_to=a.get("to") or None,
        limit=limit, offset=(page - 1) * limit,
    )
    return jsonify({
        "alerts": rows, "total": total, "page": page, "limit": limit,
        "scope": scope, "pages": (total + limit - 1) // limit,
        "labels": td.threat_type_labels(),
    })


@api_bp.route("/alerts/history/export.csv", methods=["GET"])
def alerts_history_export():
    """현재 검색 조건의 알림 이력을 CSV로 내보내기 (최대 10000건)."""
    import csv, io
    from flask import Response
    td = threat_detector()
    a = request.args
    scope = a.get("scope") or "all"
    if scope not in ("all", "live", "archive"):
        return jsonify({"error": "scope 는 all/live/archive 중 하나여야 합니다"}), 400
    rows, _total = td.search_alerts(
        scope=scope,
        severity=a.get("severity") or None,
        status=a.get("status") or None,
        threat_type=a.get("threat_type") or None,
        ip=(a.get("ip") or "").strip() or None,
        text=(a.get("text") or "").strip() or None,
        date_from=a.get("from") or None,
        date_to=a.get("to") or None,
        limit=10000, offset=0,
    )
    buf = io.StringIO()
    buf.write("﻿")  # Excel 한글 깨짐 방지 BOM
    w = csv.writer(buf)
    w.writerow(["id", "timestamp", "severity", "threat_type", "threat_label",
                "src_ip", "dst_ip", "status", "archived", "description"])
    for r in rows:
        w.writerow([r["id"], r["timestamp"], r["severity"], r["threat_type"],
                    r.get("threat_label", ""), r["src_ip"], r["dst_ip"],
                    r["status"], int(bool(r.get("archived"))), r["description"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=alert_history.csv"})


@api_bp.route("/alerts/retention", methods=["GET"])
def alerts_retention():
    """계층별 보존 현황과 변경 없는 정리 미리보기."""
    app = current_app._get_current_object()
    from modules import retention
    store = getattr(app.threat_detector, "store", None)
    if store is None:
        return jsonify({"live": 0, "archived": 0, **retention.status(app)})
    out = store.retention_stats()
    out.update(retention.status(app))
    return jsonify(out)


@api_bp.route("/alerts/retention/run", methods=["POST"])
def retention_run():
    """미리보기 후 수동 정리. 대량 영구삭제는 명시 확인이 있어야 실행한다."""
    from modules import retention
    app = current_app._get_current_object()
    before = retention.preview(app)
    data = request.get_json(silent=True) or {}
    if before["destructive_total"] > 1000 and not data.get("confirm_large"):
        return jsonify({"success": False, "requires_confirmation": True,
                        "error": "영구삭제 대상이 1,000건을 초과합니다", **before}), 409
    result = retention.run_cleanup(app, manual=True)
    audit_record("RETENTION_RUN", target="보존 정책 수동 실행",
                 detail=f"아카이브 {result['archived']} · 영구삭제 "
                        f"{result['archive_deleted'] + result['audit_deleted'] + result['files_deleted']}")
    return jsonify({"success": True, "result": result, **retention.status(app)})


@api_bp.route("/alerts/archive", methods=["POST"])
def alerts_archive():
    """N일 경과 알림을 아카이브 테이블로 이동(무손실). 기본 보존기간 사용."""
    app = current_app._get_current_object()
    store = getattr(app.threat_detector, "store", None)
    if store is None:
        return jsonify({"success": False, "error": "알림 DB 없음"}), 400
    days = request.args.get("days", app.config.get("ALERT_RETENTION_DAYS", 90), type=int)
    days = max(1, days)
    moved = store.archive_older_than(days)
    audit_record("ALERT_ARCHIVE", target=f"{days}일 경과", detail=f"{moved}건 이동")
    return jsonify({"success": True, "moved": moved, "days": days,
                    **store.retention_stats()})


@api_bp.route("/alerts/<int:alert_id>/status", methods=["PUT"])
def update_alert_status(alert_id):
    td = threat_detector()
    data = request.get_json()
    status = data.get("status")
    if status not in ("OPEN", "ACK", "CLOSED"):
        return jsonify({"error": "유효하지 않은 상태"}), 400
    ok = td.update_alert_status(alert_id, status,
                                note=data.get("note"),
                                assignee=data.get("assignee"))
    if ok:
        act = {"ACK": "ALERT_ACK", "CLOSED": "ALERT_CLOSE",
               "OPEN": "ALERT_REOPEN"}.get(status, "ALERT_ACK")
        audit_record(act, target=f"알림 #{alert_id}", detail=data.get("note") or "")
    return jsonify({"success": ok})


@api_bp.route("/alerts/<int:alert_id>/verdict", methods=["PUT"])
def update_alert_verdict(alert_id):
    """분석가의 근거 기반 정·오탐 확정. 처리 상태와 별도로 저장한다."""
    td = threat_detector()
    data = request.get_json(silent=True) or {}
    verdict = data.get("verdict")
    allowed = ("UNREVIEWED", "INVESTIGATING", "TRUE_POSITIVE", "FALSE_POSITIVE")
    if verdict not in allowed:
        return jsonify({"error": "유효하지 않은 판정"}), 400
    reason = str(data.get("reason") or "").strip()[:500]
    if verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE") and len(reason) < 3:
        return jsonify({"error": "확정 판정에는 근거를 3자 이상 입력하세요"}), 400
    actor = str(request.cookies.get("user") or "")
    from flask import session
    actor = session.get("user") or actor or "analyst"
    ok = td.set_alert_verdict(alert_id, verdict, actor, reason)
    if ok:
        audit_record("ALERT_VERDICT", target=f"알림 #{alert_id}",
                     detail=f"{verdict} · {reason}")
    return jsonify({"success": ok, "verdict": verdict})


# ------------------------------------------------------------------ #
#  Sysmon
# ------------------------------------------------------------------ #

@api_bp.route("/sysmon/events", methods=["GET"])
def sysmon_events():
    sp = sysmon_parser()
    limit    = int(request.args.get("limit", 100))
    event_id = request.args.get("event_id", type=int)
    severity = request.args.get("severity")
    return jsonify({
        "events": sp.get_events(limit=limit, event_id=event_id, severity=severity),
        "stats":  sp.get_stats(),
    })


# ------------------------------------------------------------------ #
#  해시 검사
# ------------------------------------------------------------------ #

@api_bp.route("/hash/check", methods=["POST"])
def check_hash():
    hc = hash_checker()
    data = request.get_json()
    hash_val = data.get("hash", "").strip()
    algo     = data.get("algorithm", "sha256")
    if not hash_val:
        return jsonify({"error": "hash 값이 필요합니다"}), 400
    return jsonify(hc.check_hash(hash_val, algo))


@api_bp.route("/hash/file", methods=["POST"])
def hash_file():
    hc = hash_checker()
    data = request.get_json()
    path = data.get("path", "")
    if not path:
        return jsonify({"error": "파일 경로가 필요합니다"}), 400
    if not _hash_scan_allowed(path):
        return jsonify({"error": "허용되지 않은 경로입니다 (HASH_SCAN_ALLOWED_DIRS 참고)"}), 403
    return jsonify(hc.scan_file(path))


# ------------------------------------------------------------------ #
#  YARA 악성코드 스캔 (내용 기반 — 해시 대조가 못 잡는 변종을 잡는다)
# ------------------------------------------------------------------ #

def _yara():
    return getattr(current_app._get_current_object(), "yara", None)


@api_bp.route("/yara/status", methods=["GET"])
def yara_status():
    scanner = _yara()
    if scanner is None:
        return jsonify({"running": False, "stats": {"enabled": False},
                        "rules": [], "matches": [],
                        "reason": "YARA 스캐너가 비활성입니다 (YARA_ENABLED)"})
    return jsonify(scanner.get_status())


@api_bp.route("/yara/scan", methods=["POST"])
def yara_scan():
    """파일 또는 디렉터리를 YARA 룰로 스캔한다.

    해시 스캔과 **같은 경로 제한**을 쓴다 — 스캐너가 임의 경로를 읽는 순간
    그 자체가 취약점이다.
    """
    scanner = _yara()
    if scanner is None:
        return jsonify({"error": "YARA 스캐너가 비활성입니다"}), 503
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    if not path:
        return jsonify({"error": "파일 경로가 필요합니다"}), 400
    if not _hash_scan_allowed(path):
        return jsonify({"error": "허용되지 않은 경로입니다 (HASH_SCAN_ALLOWED_DIRS 참고)"}), 403
    import os
    if os.path.isdir(path):
        result = scanner.scan_directory(path)
    else:
        result = scanner.scan_file(path)
    audit_record("YARA_SCAN", path,
                 f"매치 {len(result.get('matches') or result.get('results') or [])}건")
    return jsonify(result)


@api_bp.route("/yara/reload", methods=["POST"])
def yara_reload():
    """룰 파일을 고친 뒤 재기동 없이 다시 컴파일한다."""
    scanner = _yara()
    if scanner is None:
        return jsonify({"error": "YARA 스캐너가 비활성입니다"}), 503
    loaded = scanner.load_rules()
    audit_record("YARA_RELOAD", "rules", f"{loaded}개 로드")
    return jsonify({"loaded": loaded, "stats": scanner.get_status()["stats"]})


@api_bp.route("/hash/history", methods=["GET"])
def hash_history():
    hc = hash_checker()
    return jsonify({"history": hc.get_scan_history()})
