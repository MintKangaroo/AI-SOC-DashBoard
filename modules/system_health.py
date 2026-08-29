"""
모듈 헬스 집계 — 등록된 전 서비스의 가동 상태·동작 모드(실측/데모/비활성)를
한 곳에서 수집한다. 각 모듈을 수정하지 않고 방어적으로 조회하며,
개별 모듈 조회가 실패해도 전체 패널은 깨지지 않는다.

모드 의미:
  real  : 실제 데이터/실측 (psutil·실로그·외부 API 등)
  demo  : 합성 데이터 (fallback)
  off   : 비활성 (미설정으로 동작 안 함, 예: ntfy 미설정)
  live  : 항상 실동작하는 라이브러리성 모듈 (모드 개념 없음)
  down  : running=False (기동 실패/정지)
"""

# (app 속성명, 표시명, 카테고리) — 사이드바 그룹 순서와 정렬
SPECS = [
    # 수집·탐지
    ("packet_analyzer", "패킷 분석",        "수집·탐지"),
    ("threat_detector", "위협 탐지 엔진",   "수집·탐지"),
    ("sysmon_parser",   "Sysmon 파서",      "수집·탐지"),
    ("edr",             "EDR 센서",         "수집·탐지"),
    ("net_monitor",     "네트워크 관제",    "수집·탐지"),
    ("siem_collector",  "SIEM 수집기",      "수집·탐지"),
    ("syslog_receiver", "Syslog 수신기",    "수집·탐지"),
    ("honeypot",        "허니팟",           "수집·탐지"),
    ("authlog",         "SSH 인증 로그",    "수집·탐지"),
    # 위협 분석
    ("ml_analyst",      "ML 분석 엔진",     "위협 분석"),
    ("ai_analyst",      "Claude AI 분석",   "위협 분석"),
    ("threat_intel",    "위협 인텔리전스",  "위협 분석"),
    ("ip_reputation",   "IP 평판 (AbuseIPDB)", "위협 분석"),
    ("mitre_tracker",   "MITRE ATT&CK 매퍼", "위협 분석"),
    ("sigma",           "Sigma 룰 엔진",    "위협 분석"),
    ("yara",            "YARA 악성코드 스캐너", "위협 분석"),
    ("decision_support","ML 의사결정 지원", "위협 분석"),
    ("watchlist",       "IOC 워치리스트",   "위협 분석"),
    ("siem_correlator", "SIEM 상관관계",    "위협 분석"),
    # 대응
    ("soar",            "SOAR 자동대응",    "대응"),
    ("incidents",       "인시던트 관리",    "대응"),
    ("attack_map",      "공격 지도 (GeoIP)", "대응"),
    ("notifier",        "푸시 알림 (ntfy)", "대응"),
    # 진단
    ("vuln_scanner",    "취약점 스캐너",    "진단"),
    ("web_fuzzer",      "웹 퍼저",          "진단"),
    ("patch_manager",   "패치 관리 (Ansible)", "진단"),
    ("purple",          "퍼플팀 하네스",    "진단"),
    # 시스템
    ("hash_checker",    "해시 검사기",      "시스템"),
    ("daily_report",    "일일 AI 리포트",   "시스템"),
    ("audit",           "감사 로그",        "시스템"),
]

# 모드 개념이 없는(항상 실동작) 라이브러리성 모듈
_LIVE_MODULES = {"threat_detector", "sysmon_parser", "mitre_tracker",
                 "decision_support", "incidents", "hash_checker", "sigma", "audit",
                 "watchlist", "siem_correlator"}


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _eff_stats(stats, status):
    """지표 딕셔너리 확정: get_stats 우선, 없으면 get_status 안의 'stats'."""
    if isinstance(stats, dict):
        return stats
    if isinstance(status, dict) and isinstance(status.get("stats"), dict):
        return status["stats"]
    return {}


def _extract_mode(key, svc, eff, status, demo_default):
    """모듈별 동작 모드 판별."""
    # 1) 지표에 명시적 mode 가 있으면 그대로 사용 (edr/net_monitor/authlog 등)
    if eff.get("mode") in ("real", "demo", "off"):
        return eff["mode"]
    # 2) 모듈별 특수 규칙
    if key == "ai_analyst":
        return "real" if (status or {}).get("available") else "demo"
    if key == "notifier":
        return "real" if (status or {}).get("active") else "off"
    if key == "siem_collector":
        # 실제 접근 로그 소스가 하나라도 존재하면 실모드
        srcs = (status or {}).get("sources") or []
        return "real" if any(s.get("exists") for s in srcs) else "demo"
    if key in _LIVE_MODULES:
        return "live"
    # 3) 전역 DEMO_MODE 기본값
    return "demo" if demo_default else "real"


def _extract_detail(key, eff, status):
    """모듈별 대표 지표 한 줄."""
    s = eff if isinstance(eff, dict) else {}
    st = status if isinstance(status, dict) else {}
    def g(d, *keys):
        """중첩 경로 조회: g(d, 'a', 'b') → d['a']['b']."""
        cur = d
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return None
            cur = cur[k]
        return cur
    picks = {
        "packet_analyzer": ("총 패킷", g(s, "total_packets")),
        "threat_detector": ("총 알림", g(s, "total")),
        "sysmon_parser":   ("이벤트", g(s, "total_events")),
        "edr":             ("탐지", g(s, "detections")),
        "net_monitor":     ("악성 연결", g(s, "malicious_conns")),
        "siem_collector":  ("이벤트", g(s, "total_events")),
        "syslog_receiver": ("수신", g(s, "received")),
        "honeypot":        ("유인 접촉", g(s, "total_hits")),
        "authlog":         ("실패 시도", g(s, "failed")),
        "ml_analyst":      ("IF 이상탐지", g(s, "if_anomalies")),
        "ai_analyst":      ("분석", g(st, "total_analyses")),
        "threat_intel":    ("악성 IP", g(s, "bad_ip_count")),
        "ip_reputation":   ("조회", g(s, "total_checks")),
        "sigma":           ("매치", g(s, "matches")),
        "soar":            ("자동조치", g(s, "total_actions")),
        "incidents":       ("활성 케이스", g(s, "active")),
        "vuln_scanner":    ("취약점", g(s, "vulns")),
        "web_fuzzer":      ("발견", g(s, "findings")),
        "patch_manager":   ("보안 패치", g(s, "security")),
        "notifier":        ("전송", g(st, "stats", "sent")),
    }
    label, val = picks.get(key, (None, None))
    if val is None:
        return ""
    try:
        val = f"{int(val):,}"
    except (ValueError, TypeError):
        val = str(val)
    return f"{label} {val}"


def collect(app):
    """전 서비스 헬스 목록 + 요약 반환."""
    demo_default = bool(getattr(app, "config", {}).get("DEMO_MODE", True)) \
        if hasattr(app, "config") else True

    modules = []
    for key, label, category in SPECS:
        svc = getattr(app, key, None)
        if svc is None:
            modules.append({"key": key, "label": label, "category": category,
                            "running": False, "mode": "down", "detail": "미등록"})
            continue
        running_attr = getattr(svc, "running", None)
        running = True if running_attr is None else bool(running_attr)
        stats  = _safe(getattr(svc, "get_stats", lambda: None))
        status = _safe(getattr(svc, "get_status", lambda: None))
        eff = _eff_stats(stats, status)
        if not running:
            mode = "down"
        else:
            mode = _extract_mode(key, svc, eff, status, demo_default)
        detail = _extract_detail(key, eff, status)
        modules.append({"key": key, "label": label, "category": category,
                        "running": running, "mode": mode, "detail": detail})

    summary = {
        "total": len(modules),
        "running": sum(1 for m in modules if m["running"]),
        "down":    sum(1 for m in modules if not m["running"]),
        "real":    sum(1 for m in modules if m["mode"] == "real"),
        "demo":    sum(1 for m in modules if m["mode"] == "demo"),
        "off":     sum(1 for m in modules if m["mode"] == "off"),
        "demo_mode": demo_default,
    }
    return {"modules": modules, "summary": summary}
