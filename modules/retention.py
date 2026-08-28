"""계층별 데이터 보존 관리.

활성 알림은 영구삭제하지 않고 아카이브로 이동한다. 영구삭제는 아카이브,
감사 로그, 파일 산출물에 각자의 장기 보존 기간을 적용한다.
"""
import glob
import os
import threading
import time
from collections import deque
from datetime import datetime

from modules.logging_setup import get_logger

_log = get_logger(__name__)

_FILE_TARGETS = ["logs/*", "data/*.log", "data/reports/*", "data/ansible/*.yml"]
_history = deque(maxlen=20)
_lock = threading.Lock()


def _policy(app):
    return {
        "live_days": max(1, int(app.config.get("ALERT_RETENTION_DAYS", 90))),
        "archive_days": max(30, int(app.config.get("ALERT_ARCHIVE_RETENTION_DAYS", 365))),
        "audit_days": max(30, int(app.config.get("AUDIT_RETENTION_DAYS", 365))),
        "file_days": max(1, int(app.config.get("DATA_RETENTION_DAYS", 30))),
        "feature_days": max(7, int(app.config.get("ML_FEATURE_RETENTION_DAYS", 180))),
        "dedup_days": max(7, int(app.config.get("DEDUP_RETENTION_DAYS", 90))),
        # 인시던트는 분석가의 케이스 기록이라 길게 잡는다. RESOLVED 만 대상.
        "incident_days": max(30, int(app.config.get("INCIDENT_RETENTION_DAYS", 365))),
        # 마지막 활동 후 이 기간 조용하면 자동 종료 (0 이면 비활성)
        "incident_auto_resolve_days": max(
            0, int(app.config.get("INCIDENT_AUTO_RESOLVE_DAYS", 30))),
        # SOAR 실행 이력은 운영 로그 성격. 승인 대기·진행 중은 대상에서 제외된다.
        "soar_exec_days": max(7, int(app.config.get("SOAR_EXECUTION_RETENTION_DAYS", 90))),
    }


def _file_candidates(base_dir, days):
    cutoff = time.time() - days * 86400
    return [path for pattern in _FILE_TARGETS
            for path in glob.glob(os.path.join(base_dir, pattern))
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff]


def preview(app):
    """현재 정책의 이동·삭제 예정 건수를 변경 없이 반환한다."""
    policy = _policy(app)
    store = getattr(getattr(app, "threat_detector", None), "store", None)
    alert_counts = store.retention_preview(policy["live_days"], policy["archive_days"]) \
        if store is not None else {"to_archive": 0, "archive_to_delete": 0}
    audit = getattr(app, "audit", None)
    audit_delete = audit.count_older_than(policy["audit_days"]) if audit is not None else 0
    incidents = getattr(app, "incidents", None)
    inc_delete = incidents.count_purgeable(policy["incident_days"]) if incidents else 0
    auto_days = policy["incident_auto_resolve_days"]
    inc_auto = (incidents.count_auto_resolvable(auto_days)
                if incidents is not None and auto_days else 0)
    exec_store = getattr(getattr(app, "soar", None), "execution_store", None)
    exec_delete = (exec_store.count_purgeable(policy["soar_exec_days"])
                   if exec_store is not None else 0)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = len(_file_candidates(base_dir, policy["file_days"]))
    return {"policy": policy, **alert_counts, "audit_to_delete": audit_delete,
            "files_to_delete": files,
            "incidents_to_delete": inc_delete,
            "incidents_to_auto_resolve": inc_auto,
            "soar_executions_to_delete": exec_delete,
            "destructive_total": (alert_counts["archive_to_delete"] + audit_delete
                                  + files + inc_delete + exec_delete)}


def run_cleanup(app, manual=False):
    """정책에 따라 1회 정리한다. 활성 알림은 항상 무손실 아카이브한다."""
    before = preview(app)
    policy = before["policy"]
    store = getattr(getattr(app, "threat_detector", None), "store", None)
    moved = deleted_archive = deleted_audit = deleted_files = 0
    if store is not None:
        moved = store.archive_older_than(policy["live_days"])
        deleted_archive = store.purge_archive_older_than(policy["archive_days"])
    audit = getattr(app, "audit", None)
    if audit is not None:
        deleted_audit = audit.purge_older_than(policy["audit_days"])
    # ML 트래픽 피처 — 재학습 소스이므로 알림보다 길게 보존한다(기본 180일)
    deleted_features = 0
    feature_store = getattr(getattr(app, "ml_analyst", None), "store", None)
    if feature_store is not None:
        try:
            deleted_features = feature_store.purge_older_than(policy["feature_days"])
        except Exception as e:
            _log.error(f"[Retention] ML 피처 정리 실패: {e}")
    # 억제·병합 이벤트 보관분 — 잘못 억제한 것을 되짚는 근거라 함부로 줄이지 않는다
    deleted_dedup = 0
    dedup = getattr(app, "alert_dedup", None)
    if dedup is not None:
        try:
            deleted_dedup = dedup.purge_older_than(policy["dedup_days"])
        except Exception as e:
            _log.error(f"[Retention] 억제 이벤트 정리 실패: {e}")
    # 차단 결정 기록 — 자동 차단의 근거다. 감사 로그와 같은 기간(기본 365일)을 쓴다.
    deleted_decisions = 0
    decisions = getattr(app, "block_decisions", None)
    if decisions is not None:
        try:
            deleted_decisions = decisions.purge_older_than()
        except Exception as e:
            _log.error(f"[Retention] 차단 결정 기록 정리 실패: {e}")
    # 인시던트: 자동 종료 → 그 다음 정리. 순서가 중요하다 — 방금 종료된 건은
    # updated 가 갱신되므로 이번 정리 대상이 되지 않는다(보존기간이 새로 시작).
    resolved_incidents = 0
    deleted_incidents = 0
    incidents = getattr(app, "incidents", None)
    if incidents is not None:
        auto_days = policy["incident_auto_resolve_days"]
        if auto_days:
            try:
                resolved_incidents = incidents.auto_resolve_stale(auto_days)
            except Exception as e:
                _log.error(f"[Retention] 인시던트 자동 종료 실패: {e}")
        try:
            deleted_incidents = incidents.purge_resolved_older_than(policy["incident_days"])
        except Exception as e:
            _log.error(f"[Retention] 인시던트 정리 실패: {e}")

    # SOAR 실행 이력 — 종료된 것만. 승인 대기는 사람의 결정을 기다리므로 보존한다.
    deleted_execs = 0
    exec_store = getattr(getattr(app, "soar", None), "execution_store", None)
    if exec_store is not None:
        try:
            deleted_execs = exec_store.purge_terminal_older_than(policy["soar_exec_days"])
        except Exception as e:
            _log.error(f"[Retention] SOAR 실행 이력 정리 실패: {e}")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for path in _file_candidates(base_dir, policy["file_days"]):
        try:
            os.remove(path)
            deleted_files += 1
        except OSError:
            pass
    result = {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              "trigger": "manual" if manual else "auto", "archived": moved,
              "archive_deleted": deleted_archive, "audit_deleted": deleted_audit,
              "files_deleted": deleted_files, "features_deleted": deleted_features,
              "dedup_deleted": deleted_dedup,
              "incidents_auto_resolved": resolved_incidents,
              "incidents_deleted": deleted_incidents,
              "soar_executions_deleted": deleted_execs,
              "block_decisions_deleted": deleted_decisions,
              "policy": policy}
    with _lock:
        _history.appendleft(result)
    if any((moved, deleted_archive, deleted_audit, deleted_files,
            deleted_features, deleted_dedup, deleted_incidents, deleted_execs,
            resolved_incidents, deleted_decisions)):
        _log.info(f"[Retention] 알림 {moved}건 아카이브 · 아카이브 {deleted_archive}건 · "
              f"감사 {deleted_audit}건 · 파일 {deleted_files}건 · "
              f"ML피처 {deleted_features}건 · 억제이벤트 {deleted_dedup}건 · "
              f"인시던트 자동종료 {resolved_incidents}건/삭제 {deleted_incidents}건 · "
              f"SOAR실행 {deleted_execs}건 삭제")
    return result


def status(app):
    out = preview(app)
    with _lock:
        out["history"] = list(_history)
    return out


def start(app, interval_hours=6):
    """시작 1분 후 최초 실행하고 이후 설정 주기로 정리한다."""
    def _loop():
        time.sleep(60)
        while True:
            try:
                run_cleanup(app)
            except Exception as e:
                _log.error(f"[Retention] 정리 루프 오류: {e}")
            time.sleep(max(1, float(interval_hours)) * 3600)
    threading.Thread(target=_loop, daemon=True).start()
    p = _policy(app)
    _log.info(f"[Retention] 활성 {p['live_days']}일→아카이브 · 아카이브/감사 "
          f"{p['archive_days']}/{p['audit_days']}일 · 파일 {p['file_days']}일 · "
          f"ML피처 {p['feature_days']}일 · 인시던트(RESOLVED) {p['incident_days']}일 · "
          f"SOAR실행(종료분) {p['soar_exec_days']}일"
          + (f" · 인시던트 자동종료 {p['incident_auto_resolve_days']}일"
             if p['incident_auto_resolve_days'] else " · 인시던트 자동종료 비활성"))
