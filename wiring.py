"""서비스 배선 — 전 모듈 인스턴스 생성·상호 의존 주입·app 등록·백그라운드 시작.

create_app() 을 Flask 앱 구성(인증·라우트·소켓 이벤트)에 집중시키기 위해
서비스 계층 배선을 이 모듈로 분리했다. 의존 방향은 build_services() 안의
주석(예: `threat_detector.soar = soar`)으로 명시한다.
"""
from modules.packet_analyzer import PacketAnalyzer
from modules.threat_detector import ThreatDetector
from modules.sysmon_parser import SysmonParser
from modules.hash_checker import HashChecker
from modules.ai_analyst import AIAnalyst
from modules.ml_analyst import MLAnalyst
from modules.geoip import AttackMapTracker
from modules.mitre_attack import MitreTracker
from modules.threat_intel import ThreatIntel
from modules.ip_reputation import IPReputation
from modules.edr import EDRSensor
from modules.net_monitor import NetworkMonitor
from modules.patch_manager import PatchManager
from modules.vuln_scanner import VulnScanner
from modules.web_fuzzer import WebFuzzer
from modules.notifier import Notifier
from modules.sigma_engine import SigmaEngine
from modules.daily_report import DailyReport
from modules.purple_team import PurpleTeam
from modules.access_log_parser import AccessLogCollector
from modules.soar import SOAREngine
from modules.decision_support import DecisionSupport
from modules.incidents import IncidentManager
from modules.authlog_parser import AuthLogMonitor
from modules.syslog_receiver import SyslogReceiver
from modules.honeypot import Honeypot
from modules.siem_correlation import SIEMCorrelator
from modules.audit_log import AuditLog
from modules.watchlist import Watchlist
from modules.virustotal import VirusTotalClient
from modules.snort_monitor import SnortMonitor
from modules.alert_dedup import AlertDeduplicator


def build_services(app, socketio):
    """모든 서비스 인스턴스를 생성·상호 배선하고 app.<name> 으로 등록한다."""
    mitre_tracker   = MitreTracker(socketio)
    attack_map      = AttackMapTracker(socketio)
    threat_detector = ThreatDetector(socketio, app.config,
                                     mitre_tracker=mitre_tracker,
                                     attack_map=attack_map)
    packet_analyzer = PacketAnalyzer(socketio, app.config,
                                     threat_detector=threat_detector)
    sysmon_parser   = SysmonParser(socketio, app.config, mitre_tracker=mitre_tracker)
    hash_checker    = HashChecker(app.config.get("MALICIOUS_HASH_DB"))
    virustotal      = VirusTotalClient(app.config)
    ml_analyst      = MLAnalyst(socketio, demo=app.config.get("DEMO_MODE", True))
    ai_analyst      = AIAnalyst(socketio, ml_analyst=ml_analyst)
    threat_intel    = ThreatIntel(socketio, packet_analyzer=packet_analyzer,
                                  mitre_tracker=mitre_tracker)
    threat_detector.threat_intel = threat_intel   # IoC 기반 정탐 신뢰도 가중

    # 중복제거·억제 레이어 — 탐지 엔진과 SOAR 사이. 알림을 버리지 않고 병합한다.
    alert_dedup = AlertDeduplicator(app.config)
    threat_detector.dedup = alert_dedup

    ip_reputation = IPReputation(socketio, app.config)
    threat_detector.ip_reputation = ip_reputation  # AbuseIPDB 평판 → 정탐/오탐 근거

    siem_sources = None
    if app.config.get("SIEM_ACCESS_LOGS"):
        siem_sources = [{"name": n.strip(), "path": p.strip()}
                        for n, _, p in (item.partition("=")
                                        for item in app.config["SIEM_ACCESS_LOGS"].split(";"))
                        if n.strip() and p.strip()]
    siem_collector  = AccessLogCollector(socketio, sources=siem_sources,
                                         mitre_tracker=mitre_tracker,
                                         attack_map=attack_map)

    soar = SOAREngine(socketio, app.config, ai_analyst=ai_analyst,
                      ml_analyst=ml_analyst, threat_detector=threat_detector)
    soar.virustotal = virustotal
    threat_detector.soar = soar
    siem_collector.soar  = soar
    threat_intel.soar    = soar
    snort = SnortMonitor(socketio, app.config, threat_detector=threat_detector)

    decision = DecisionSupport(socketio)
    threat_detector.decision = decision   # 클러스터 prior → 알림 신뢰도 반영
    soar.decision            = decision   # AI/규칙 판정 → 클러스터 학습

    incidents = IncidentManager(
        socketio,
        store_path="data/incidents.db",
        save_debounce_seconds=app.config.get("INCIDENT_SAVE_DEBOUNCE_SECONDS", 5),
    )
    soar.incidents = incidents            # 정탐 알림 → 인시던트 자동 승격

    # 실제 SSH 인증 로그 감시 (auth.log) → BRUTE_FORCE 를 파이프라인에 주입
    authlog = AuthLogMonitor(socketio, app.config, threat_detector=threat_detector)

    # Syslog 수신 (KR/USA 원격 침해시도) → 접속시도/공격을 파이프라인에 주입
    syslog_receiver = SyslogReceiver(socketio, app.config,
                                     threat_detector=threat_detector,
                                     mitre_tracker=mitre_tracker, attack_map=attack_map)

    # 허니팟 (유인 서비스) → 접촉 자체가 고신뢰 침해지표 → 파이프라인 주입
    honeypot = Honeypot(socketio, app.config, threat_detector=threat_detector,
                        mitre_tracker=mitre_tracker, attack_map=attack_map)

    # SIEM 상관관계 분석 → 알림 스트림을 규칙으로 엮어 CORRELATED 상관 탐지 발화
    siem_correlator = SIEMCorrelator(socketio, app.config, threat_detector=threat_detector)
    threat_detector.siem_correlator = siem_correlator

    # Sigma 룰 엔진 (업계 표준 탐지룰) → EDR 프로세스 이벤트를 표준룰로 평가
    sigma = SigmaEngine(socketio, app.config, threat_detector=threat_detector,
                        mitre_tracker=mitre_tracker)

    # AI 기반 EDR (프로세스 행위 관제) → HIGH/CRITICAL 은 AI 트리아지 파이프라인에 투입
    edr = EDRSensor(socketio, app.config, threat_detector=threat_detector,
                    mitre_tracker=mitre_tracker, ai_analyst=ai_analyst,
                    ip_reputation=ip_reputation)
    edr.sigma = sigma   # EDR 스캔 프로세스를 Sigma 룰로도 평가

    # 네트워크 모니터링 관제 (연결·포트·대역폭·타깃 헬스체크)
    net_monitor = NetworkMonitor(socketio, app.config, ip_reputation=ip_reputation,
                                 threat_detector=threat_detector)

    # 푸시 알림 (ntfy) — 정탐/차단만 폰으로
    notifier = Notifier(socketio, app.config)
    soar.notifier = notifier

    # 자동화 취약점 패치 (Ansible)
    patch_manager = PatchManager(socketio, app.config)

    # 취약점 스캐너 (포트/서비스/CVE)
    vuln_scanner = VulnScanner(socketio, app.config)

    # 웹 엔드포인트 퍼저 (견고성 점검)
    web_fuzzer = WebFuzzer(socketio, app.config)

    # 퍼플팀 공격 시뮬레이션 하네스 (탐지 파이프라인 검증)
    purple = PurpleTeam(socketio, app.config, sigma=sigma, edr=edr, authlog=authlog,
                        ip_reputation=ip_reputation, net_monitor=net_monitor,
                        threat_detector=threat_detector)

    # 일일 AI 리포트 (전 모듈 지표 집계 → Claude 브리핑)
    daily_report = DailyReport(socketio, app.config, ai_analyst=ai_analyst, services={
        "threat_detector": threat_detector, "soar": soar, "edr": edr,
        "sigma": sigma, "net_monitor": net_monitor, "authlog": authlog,
        "ip_reputation": ip_reputation, "mitre": mitre_tracker, "incidents": incidents,
    })

    # 전역 감사 로그 (분석가 조치 기록)
    audit = AuditLog(app.config.get("AUDIT_DB", "data/audit.db"))

    # IOC 워치리스트 (능동 헌팅) → 알림 파이프라인에서 대조
    watchlist = Watchlist(socketio, app.config.get("WATCHLIST_DB", "data/watchlist.db"))
    threat_detector.watchlist = watchlist

    # app 컨텍스트에 서비스 등록
    app.alert_dedup     = alert_dedup
    app.audit           = audit
    app.watchlist       = watchlist
    app.packet_analyzer = packet_analyzer
    app.threat_detector = threat_detector
    app.sysmon_parser   = sysmon_parser
    app.hash_checker    = hash_checker
    app.virustotal      = virustotal
    app.ai_analyst      = ai_analyst
    app.ml_analyst      = ml_analyst
    app.attack_map      = attack_map
    app.mitre_tracker   = mitre_tracker
    app.threat_intel    = threat_intel
    app.ip_reputation   = ip_reputation
    app.siem_collector  = siem_collector
    app.syslog_receiver = syslog_receiver
    app.honeypot        = honeypot
    app.siem_correlator = siem_correlator
    app.soar            = soar
    app.decision_support = decision
    app.incidents        = incidents
    app.authlog          = authlog
    app.edr              = edr
    app.net_monitor      = net_monitor
    app.patch_manager    = patch_manager
    app.vuln_scanner     = vuln_scanner
    app.web_fuzzer       = web_fuzzer
    app.notifier         = notifier
    app.sigma            = sigma
    app.daily_report     = daily_report
    app.purple           = purple
    app.snort            = snort


def start_services(app, socketio):
    """백그라운드 서비스 시작 + ML 피드 루프. build_services() 이후 호출."""
    demo = app.config.get("DEMO_MODE", True)
    iface = app.config.get("CAPTURE_INTERFACE")

    app.packet_analyzer.start(interface=iface, demo=demo)
    app.threat_detector.start(demo=demo)
    app.snort.start(demo=False)       # Snort는 합성 이벤트를 만들지 않음
    app.sysmon_parser.start(demo=demo)
    app.ai_analyst.start()
    app.ml_analyst.start(demo=demo)   # 피처 origin(real/demo) 구분 저장
    app.attack_map.start(demo=demo)
    app.threat_intel.start(demo=demo)
    app.ip_reputation.set_own_ips(getattr(app.soar, "_own_ips", set()))
    app.ip_reputation.start(demo=demo)
    app.siem_collector.start(demo=demo)
    app.soar.start(demo=demo)
    app.authlog.start(demo=demo)      # auth.log 있으면 실모드, 없으면 데모
    app.syslog_receiver.start(demo=demo)  # udp/tcp 5514 수신, 바인딩 실패 시 데모
    app.honeypot.start(demo=demo)         # 유인 서비스 리스너, 바인딩 실패 시 데모
    app.siem_correlator.start(demo=demo)  # 알림 스트림 상관관계 분석(항상 실동작)
    app.sigma.start(demo=demo)        # Sigma 룰 로드 (EDR 보다 먼저)
    app.edr.start(demo=demo)          # psutil 있으면 실센서, 없으면 데모
    app.net_monitor.start(demo=demo)
    app.patch_manager.start(demo=demo)   # apt 스캔은 읽기전용, 실제 패치는 수동
    app.vuln_scanner.start(demo=demo)    # 포트/서비스/CVE 스캔 (연결 스캔, 온디맨드)
    app.web_fuzzer.start(demo=demo)      # 웹 견고성 퍼징 (본인 서버만, 온디맨드)
    app.daily_report.start(demo=demo)    # 매일 정해진 시각 브리핑 + 시작 시 1회
    app.purple.start(demo=demo)          # 온디맨드 탐지 검증 (자동 실행 없음)
    print(f"[Notify] ntfy 푸시 "
          f"{'활성' if app.notifier.active else '비활성(NTFY_ENABLED/NTFY_TOPIC 설정 시 폰 알림)'}")

    # 계층별 보존: 활성 알림→아카이브, 오래된 아카이브/감사/파일만 영구 삭제
    from modules import retention
    retention.start(app, interval_hours=app.config.get("DATA_RETENTION_INTERVAL_HOURS", 6))

    # ML 분석기에 패킷 통계 주기적 공급
    import threading as _t

    def _ml_feed_loop():
        import time as _time
        while True:
            _time.sleep(3)
            try:
                app.ml_analyst.feed_traffic(app.packet_analyzer.get_stats())
            except Exception:
                pass
    _t.Thread(target=_ml_feed_loop, daemon=True).start()
