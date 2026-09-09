"""킬체인 상관관계 — 같은 출발지의 알림들을 시간 윈도우로 묶어 '공격 캠페인'으로 구성.

개별 알림은 점(event)일 뿐이지만, 한 공격자의 포트스캔 → 무차별대입 → C2통신을
MITRE 전술(kill-chain) 순서로 엮으면 하나의 '공격 스토리'가 된다.
알림 피로를 줄이고 공격 진행 단계를 한눈에 파악하기 위한 뷰.
"""
from datetime import datetime
from modules.mitre_attack import TACTICS, THREAT_MAPPING
from modules.provenance import provenance

_FMT = "%Y-%m-%d %H:%M:%S"
_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# 전술 id → kill-chain 순서/한글명 (TACTICS 정의 순서 = 킬체인 순서)
_TACTIC_ORDER = {t["id"]: i for i, t in enumerate(TACTICS)}
_TACTIC_KO = {t["id"]: t["ko"] for t in TACTICS}
_TACTIC_NAME = {t["id"]: t["name"] for t in TACTICS}


def _parse(ts):
    try:
        return datetime.strptime(ts, _FMT)
    except (ValueError, TypeError):
        return None


def _primary_tactic(threat_type):
    """위협유형의 대표 전술 id (kill-chain 단계 판정용)."""
    m = THREAT_MAPPING.get(threat_type)
    return m[0][0] if m else None


def build_campaigns(rows, window_minutes=30, min_alerts=2, labels=None):
    """알림 rows → 공격 캠페인 목록.

    rows: [{id, threat_type, severity, src_ip, dst_ip, timestamp}] (시간 오름차순)
    같은 src_ip 안에서 인접 알림 간격이 window 이내면 한 캠페인으로 묶는다.
    """
    labels = labels or {}
    window = window_minutes * 60
    by_ip = {}
    for r in rows:
        by_ip.setdefault((r["src_ip"], provenance(r)["state"]), []).append(r)

    campaigns = []
    for (ip, _source), arr in by_ip.items():
        arr.sort(key=lambda r: r["timestamp"])
        # 시간 간격으로 세션 분할
        sessions, cur, last = [], [], None
        for r in arr:
            t = _parse(r["timestamp"])
            if last is not None and t is not None and (t - last).total_seconds() > window:
                sessions.append(cur); cur = []
            cur.append(r)
            last = t
        if cur:
            sessions.append(cur)

        for sess in sessions:
            if len(sess) < min_alerts:
                continue
            campaigns.append(_summarize(ip, sess, labels))

    # 다단계 진행(킬체인 스토리) 우선 → 도달 단계 → 심각도 → 규모
    campaigns.sort(key=lambda c: (c["stage_count"], c["max_stage"],
                                  c["sev_rank"], c["alert_count"]),
                   reverse=True)
    return campaigns


def _summarize(ip, sess, labels):
    start = sess[0]["timestamp"]
    end = sess[-1]["timestamp"]
    t0, t1 = _parse(start), _parse(end)
    dur_min = round((t1 - t0).total_seconds() / 60, 1) if t0 and t1 else 0

    sev_rank = max(_SEV_ORDER.get(r["severity"], 0) for r in sess)
    sev_name = next(k for k, v in _SEV_ORDER.items() if v == sev_rank)

    # 관측된 전술을 kill-chain 순서로 정리 (전술별 최초 관측 시각·위협유형)
    stage_map = {}
    for r in sess:
        tac = _primary_tactic(r["threat_type"])
        if not tac:
            continue
        if tac not in stage_map:
            stage_map[tac] = {
                "tactic_id": tac,
                "tactic": _TACTIC_NAME.get(tac, tac),
                "tactic_ko": _TACTIC_KO.get(tac, tac),
                "order": _TACTIC_ORDER.get(tac, 99),
                "first_seen": r["timestamp"],
                "threat_types": [],
            }
        tt = r["threat_type"]
        if tt not in stage_map[tac]["threat_types"]:
            stage_map[tac]["threat_types"].append(tt)
    stages = sorted(stage_map.values(), key=lambda s: s["order"])
    # 위협유형 한글 라벨 부가
    for s in stages:
        s["labels"] = [labels.get(tt, tt) for tt in s["threat_types"]]

    max_stage = max((s["order"] for s in stages), default=0)
    threat_types = []
    for r in sess:
        if r["threat_type"] not in threat_types:
            threat_types.append(r["threat_type"])

    return {
        "src_ip": ip,
        "provenance": provenance(sess[0]),
        "start": start, "end": end, "duration_min": dur_min,
        "alert_count": len(sess),
        "severity": sev_name, "sev_rank": sev_rank,
        "stages": stages,
        "stage_count": len(stages),
        "max_stage": max_stage,
        "threat_types": threat_types,
        "threat_labels": [labels.get(tt, tt) for tt in threat_types],
        "alert_ids": [r["id"] for r in sess][:200],
    }


def compute(store, hours=24, window_minutes=30, min_alerts=2, labels=None):
    if store is None:
        return {"campaigns": [], "hours": hours, "total": 0}
    rows = store.since(hours=hours)
    campaigns = build_campaigns(rows, window_minutes, min_alerts, labels)
    return {
        "hours": hours,
        "sample_size": len(rows), "sample_limit": 5000,
        "window_minutes": window_minutes,
        "total": len(campaigns),
        "multistage": sum(1 for c in campaigns if c["stage_count"] >= 2),
        "campaigns": campaigns[:100],
    }
