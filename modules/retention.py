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
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = len(_file_candidates(base_dir, policy["file_days"]))
    return {"policy": policy, **alert_counts, "audit_to_delete": audit_delete,
            "files_to_delete": files, "destructive_total":
            alert_counts["archive_to_delete"] + audit_delete + files}


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
            print(f"[Retention] ML 피처 정리 실패: {e}")
    # 억제·병합 이벤트 보관분 — 잘못 억제한 것을 되짚는 근거라 함부로 줄이지 않는다
    deleted_dedup = 0
    dedup = getattr(app, "alert_dedup", None)
    if dedup is not None:
        try:
            deleted_dedup = dedup.purge_older_than(policy["dedup_days"])
        except Exception as e:
            print(f"[Retention] 억제 이벤트 정리 실패: {e}")
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
              "policy": policy}
    with _lock:
        _history.appendleft(result)
    if any((moved, deleted_archive, deleted_audit, deleted_files,
            deleted_features, deleted_dedup)):
        print(f"[Retention] 알림 {moved}건 아카이브 · 아카이브 {deleted_archive}건 · "
              f"감사 {deleted_audit}건 · 파일 {deleted_files}건 · "
              f"ML피처 {deleted_features}건 · 억제이벤트 {deleted_dedup}건 삭제")
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
                print(f"[Retention] 정리 루프 오류: {e}")
            time.sleep(max(1, float(interval_hours)) * 3600)
    threading.Thread(target=_loop, daemon=True).start()
    p = _policy(app)
    print(f"[Retention] 활성 {p['live_days']}일→아카이브 · 아카이브/감사 "
          f"{p['archive_days']}/{p['audit_days']}일 · 파일 {p['file_days']}일 · "
          f"ML피처 {p['feature_days']}일")
