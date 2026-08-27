"""진단·운영: 패치 · 취약점스캔 · 퍼징 · 알림 · Sigma · 리포트 · 퍼플팀
   (api_bp 공유 — api/routes.py 가 임포트해 라우트를 등록한다)"""
from flask import request, jsonify, current_app
from api._common import (api_bp)


# ------------------------------------------------------------------ #
#  자동화 취약점 패치 (Ansible)
# ------------------------------------------------------------------ #

@api_bp.route("/patch/status", methods=["GET"])
def patch_status():
    return jsonify(current_app._get_current_object().patch_manager.get_status())


@api_bp.route("/patch/scan", methods=["POST"])
def patch_scan():
    pm = current_app._get_current_object().patch_manager
    pm.scan()
    return jsonify(pm.get_status())


@api_bp.route("/patch/playbook", methods=["POST"])
def patch_playbook():
    pm = current_app._get_current_object().patch_manager
    security_only = (request.get_json() or {}).get("security_only", True)
    path, content = pm.generate_playbook(security_only=security_only)
    return jsonify({"path": path, "content": content})


@api_bp.route("/patch/run", methods=["POST"])
def patch_run():
    pm = current_app._get_current_object().patch_manager
    data = request.get_json() or {}
    mode = data.get("mode", "check")            # check(dry-run) | apply
    security_only = data.get("security_only", True)
    host_ids = data.get("hosts")                # 대상 호스트 id 목록(없으면 localhost)
    job = pm.run_job(mode=mode, security_only=security_only, host_ids=host_ids)
    return jsonify({k: job.get(k) for k in
                    ("id", "kind", "mode", "status", "playbook", "hosts", "started")})


@api_bp.route("/patch/command", methods=["POST"])
def patch_command():
    pm = current_app._get_current_object().patch_manager
    data = request.get_json() or {}
    command = data.get("command", "")
    mode = data.get("mode", "check")            # check(미리보기) | apply(실제 실행)
    host_ids = data.get("hosts")
    job = pm.run_command(command=command, host_ids=host_ids, mode=mode)
    return jsonify({k: job.get(k) for k in
                    ("id", "kind", "mode", "status", "result", "hosts", "started")})


# ------------------------------------------------------------------ #
#  취약점 스캐너 (포트/서비스/CVE)
# ------------------------------------------------------------------ #

@api_bp.route("/vulnscan/status", methods=["GET"])
def vulnscan_status():
    return jsonify(current_app._get_current_object().vuln_scanner.get_status())


@api_bp.route("/vulnscan/scan", methods=["POST"])
def vulnscan_scan():
    vs = current_app._get_current_object().vuln_scanner
    host_ids = (request.get_json() or {}).get("hosts")   # 대상(없으면 전체)
    result = vs.scan(host_ids=host_ids)
    return jsonify(result)


# ------------------------------------------------------------------ #
#  웹 엔드포인트 퍼저 (견고성 점검)
# ------------------------------------------------------------------ #

@api_bp.route("/fuzz/status", methods=["GET"])
def fuzz_status():
    return jsonify(current_app._get_current_object().web_fuzzer.get_status())


@api_bp.route("/fuzz/run", methods=["POST"])
def fuzz_run():
    wf = current_app._get_current_object().web_fuzzer
    data = request.get_json() or {}
    result = wf.run(
        target_id=data.get("target", "self"),
        paths=data.get("paths"),
        params=data.get("params"),
        method=data.get("method", "GET"),
    )
    return jsonify(result)


@api_bp.route("/fuzz/stop", methods=["POST"])
def fuzz_stop():
    current_app._get_current_object().web_fuzzer.stop_run()
    return jsonify({"status": "stopping"})


# ------------------------------------------------------------------ #
#  푸시 알림 (ntfy)
# ------------------------------------------------------------------ #

@api_bp.route("/notify/status", methods=["GET"])
def notify_status():
    return jsonify(current_app._get_current_object().notifier.get_status())


@api_bp.route("/notify/test", methods=["POST"])
def notify_test():
    n = current_app._get_current_object().notifier
    ok, detail = n.notify("✅ SOC 대시보드 테스트",
                          "푸시 알림이 정상 동작합니다. 이제 정탐/차단 시 이 폰으로 알림이 옵니다.",
                          severity="CRITICAL", dedup_key="test", force=True)
    return jsonify({"ok": ok, "detail": detail, "active": n.active})


# ------------------------------------------------------------------ #
#  Sigma 룰 엔진
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/sigma", methods=["GET"])
def sigma_status():
    return jsonify(current_app._get_current_object().sigma.get_status())


@api_bp.route("/sigma/reload", methods=["POST"])
def sigma_reload():
    sig = current_app._get_current_object().sigma
    sig.load_rules()
    return jsonify(sig.get_status())


@api_bp.route("/sigma/toggle", methods=["POST"])
def sigma_toggle():
    sig = current_app._get_current_object().sigma
    rid = (request.get_json() or {}).get("rule_id")
    state = sig.toggle_rule(rid)
    return jsonify({"rule_id": rid, "enabled": state})


@api_bp.route("/sigma/test", methods=["POST"])
def sigma_test():
    sig = current_app._get_current_object().sigma
    fields = (request.get_json() or {}).get("fields") or {}
    return jsonify({"matches": sig.test_event(fields)})


# ------------------------------------------------------------------ #
#  일일 AI 리포트
# ------------------------------------------------------------------ #

@api_bp.route("/report/status", methods=["GET"])
def report_status():
    return jsonify(current_app._get_current_object().daily_report.get_status())


@api_bp.route("/report/generate", methods=["POST"])
def report_generate():
    r = current_app._get_current_object().daily_report.generate(trigger="manual")
    return jsonify({"id": r["id"], "generated": r["generated"],
                    "briefing": r["briefing"], "highlights": r["highlights"]})


@api_bp.route("/report/<rid>", methods=["GET"])
def report_get(rid):
    r = current_app._get_current_object().daily_report.get_report(rid)
    if not r:
        return jsonify({"error": "리포트 없음"}), 404
    return jsonify(r)


# ------------------------------------------------------------------ #
#  퍼플팀 공격 시뮬레이션 (탐지 검증)
# ------------------------------------------------------------------ #

@api_bp.route("/purple/status", methods=["GET"])
def purple_status():
    return jsonify(current_app._get_current_object().purple.get_status())


@api_bp.route("/purple/run", methods=["POST"])
def purple_run():
    p = current_app._get_current_object().purple
    sid = (request.get_json() or {}).get("scenario")
    if sid and sid != "all":
        return jsonify({"result": p.run_scenario(sid)})
    return jsonify(p.run_all())
