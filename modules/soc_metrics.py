"""SOC 운영 지표 — 알림 시계열(alerts.db) + 인시던트 대응시간(MTTR) 집계.

지표 정의:
  MTTR (Mean Time To Resolve) : 인시던트 생성 → RESOLVED/CONTAINED 까지 평균 소요
  MTTA (Mean Time To Acknowledge): 인시던트 생성 → INVESTIGATING 진입 평균 소요
  오탐율                        : SOAR 자동 오탐종결 / (오탐종결 + 정탐에스컬레이션)
  종결율                        : 기간 내 CLOSED / 전체
"""
from datetime import datetime

_FMT = "%Y-%m-%d %H:%M:%S"


def _parse(ts):
    try:
        return datetime.strptime(ts, _FMT)
    except (ValueError, TypeError):
        return None


def _fmt_duration(seconds):
    if seconds is None:
        return "-"
    m = int(seconds // 60)
    if m < 60:
        return f"{m}분"
    h = m / 60
    if h < 24:
        return f"{h:.1f}시간"
    return f"{h/24:.1f}일"


def _incident_times(incidents, days):
    """인시던트 timeline 에서 MTTR/MTTA 산출. incidents: {id: inc dict}."""
    from datetime import timedelta
    cutoff = datetime.now() - timedelta(days=days)
    resolve_secs, ack_secs = [], []
    opened = resolved = 0
    for inc in incidents.values():
        created = _parse(inc.get("created"))
        if not created or created < cutoff:
            continue
        opened += 1
        first_ack = first_res = None
        for ev in inc.get("timeline", []):
            if ev.get("kind") != "status":
                continue
            ts = _parse(ev.get("ts"))
            if not ts:
                continue
            text = ev.get("text", "")
            if first_ack is None and "INVESTIGATING" in text:
                first_ack = ts
            if first_res is None and ("RESOLVED" in text or "CONTAINED" in text):
                first_res = ts
        if first_ack:
            ack_secs.append((first_ack - created).total_seconds())
        if first_res:
            resolved += 1
            resolve_secs.append((first_res - created).total_seconds())
    avg = lambda xs: (sum(xs) / len(xs)) if xs else None
    return {
        "opened": opened,
        "resolved": resolved,
        "mttr_seconds": avg(resolve_secs),
        "mtta_seconds": avg(ack_secs),
        "mttr_text": _fmt_duration(avg(resolve_secs)),
        "mtta_text": _fmt_duration(avg(ack_secs)),
    }


def compute(store, incidents=None, soar_stats=None, days=14, dedup_stats=None):
    """store: AlertStore, incidents: {id:inc}, soar_stats: dict,
    dedup_stats: AlertDeduplicator.get_stats() (없으면 지표 생략)."""
    agg = store.aggregate(days=days) if store else {
        "days": days, "total": 0, "by_day": [], "by_status": {},
        "heatmap": [[0] * 24 for _ in range(7)], "top_types": [], "top_ips": []}

    inc_times = _incident_times(incidents or {}, days)

    # 오탐율 (SOAR 누적 카운터 — 기간 무관, 참고용)
    fp_rate = None
    if soar_stats:
        fp = soar_stats.get("auto_closed_fp", 0)
        tp = soar_stats.get("escalated_tp", 0)
        if (fp + tp) > 0:
            fp_rate = round(fp / (fp + tp) * 100, 1)

    st = agg["by_status"]
    total = agg["total"] or 0
    closed = st.get("CLOSED", 0)
    close_rate = round(closed / total * 100, 1) if total else 0.0

    return {
        "days": days,
        "generated": datetime.now().strftime(_FMT),
        "kpi": {
            "total_alerts": total,
            "open": st.get("OPEN", 0),
            "ack": st.get("ACK", 0),
            "closed": closed,
            "close_rate": close_rate,
            "fp_rate": fp_rate,
            "incidents_opened": inc_times["opened"],
            "incidents_resolved": inc_times["resolved"],
            "mttr": inc_times["mttr_text"],
            "mtta": inc_times["mtta_text"],
            "mttr_seconds": inc_times["mttr_seconds"],
            "mtta_seconds": inc_times["mtta_seconds"],
        },
        "by_day": agg["by_day"],
        "by_status": st,
        "heatmap": agg["heatmap"],
        "top_types": agg["top_types"],
        "top_ips": agg["top_ips"],
        "dedup": _dedup_section(dedup_stats),
    }


def _dedup_section(stats):
    """중복제거·억제 지표. 레이어가 없으면 enabled=False 로만 알린다."""
    if not stats:
        return {"enabled": False}
    return {
        "enabled": bool(stats.get("enabled", True)),
        "seen": stats.get("seen", 0),
        "deduplicated": stats.get("deduplicated", 0),
        "suppressed": stats.get("suppressed", 0),
        "passed": stats.get("passed", 0),
        "dedup_rate": stats.get("dedup_rate", 0.0),
        "suppression_rate": stats.get("suppression_rate", 0.0),
        "reduction_rate": stats.get("reduction_rate", 0.0),
        "storms": stats.get("storms", 0),
        "active_storms": stats.get("active_storms", 0),
        "active_fingerprints": stats.get("active_fingerprints", 0),
        "window_seconds": stats.get("window_seconds"),
    }
