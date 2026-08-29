import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "soc-dashboard-secret-2024")
    DEBUG = os.getenv("DEBUG", "False") == "True"
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", 8080))

    # Packet capture settings
    CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", None)  # None = auto-detect
    MAX_PACKETS_DISPLAY = int(os.getenv("MAX_PACKETS_DISPLAY", 200))

    # 패킷 기반 탐지 임계값.
    # 기본값은 **실제로 동작하던 값**이다. 이전에는 코드에 2000/40 이 박혀 있고
    # 여기 선언된 1000/20 은 아무 데서도 읽히지 않아, .env 로 조정해도 아무 일이
    # 일어나지 않았고 문서와 실제가 2배씩 달랐다(AUDIT F-1). 문서값으로
    # 되돌리면 탐지 민감도가 조용히 2배 올라가므로 실제 동작값을 채택했다.
    DDOS_PACKET_THRESHOLD = int(os.getenv("DDOS_PACKET_THRESHOLD", 2000))  # pps per IP
    PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", 40))  # 30초 내 고유 포트
    # 정탐 신뢰도 임계값 (0~1) — 미만 알림은 '오탐 의심'으로 저장만 하고 실시간 표시 억제
    ALERT_CONFIDENCE_THRESHOLD = float(os.getenv("ALERT_CONFIDENCE_THRESHOLD", 0.5))
    DATA_EXFIL_BYTES_THRESHOLD = int(os.getenv("DATA_EXFIL_BYTES_THRESHOLD", 500_000_000))
    DATA_EXFIL_WINDOW_SECONDS = int(os.getenv("DATA_EXFIL_WINDOW_SECONDS", 300))
    DATA_EXFIL_ALLOWLIST = os.getenv("DATA_EXFIL_ALLOWLIST", "")

    # Snort IDS fast-alert 연동 (탐지만 수행, 방화벽 차단은 SOAR가 별도 결정)
    SNORT_ENABLED = os.getenv("SNORT_ENABLED", "True")
    SNORT_ALERT_PATH = os.getenv("SNORT_ALERT_PATH", "/var/log/snort/snort.alert.fast")
    SNORT_POLL_INTERVAL = float(os.getenv("SNORT_POLL_INTERVAL", 0.5))
    SNORT_INTERFACE = os.getenv("SNORT_INTERFACE", "eth0")
    SNORT_HOME_NET = os.getenv("SNORT_HOME_NET", "172.23.160.0/20")
    SNORT_BLOCK_EXCLUDED_SIDS = os.getenv("SNORT_BLOCK_EXCLUDED_SIDS", "254")

    # Sysmon log path (Windows)
    SYSMON_LOG_CHANNEL = os.getenv("SYSMON_LOG_CHANNEL", "Microsoft-Windows-Sysmon/Operational")

    # Known malicious hash lists path
    MALICIOUS_HASH_DB = os.getenv("MALICIOUS_HASH_DB", "data/malicious_hashes.txt")

    # SIEM 접근 로그 소스 — "이름=경로;이름=경로" (비우면 기본 자동매매 KR/USA 로그)
    SIEM_ACCESS_LOGS = os.getenv("SIEM_ACCESS_LOGS", "")
    SIEM_EXFIL_MIN_BYTES = int(os.getenv("SIEM_EXFIL_MIN_BYTES", 500_000_000))

    # SIEM 상관관계 분석 — siem_correlation 이 읽고 있었으나 여기에도
    # .env.example 에도 없어 설정 자체가 불가능했다(AUDIT F-1 역방향).
    SIEM_CORR_WINDOW = float(os.getenv("SIEM_CORR_WINDOW", 600))        # 상관 윈도우(초)
    SIEM_CORR_COOLDOWN = float(os.getenv("SIEM_CORR_COOLDOWN", 300))    # 규칙별 재발화 간격
    SIEM_CORR_MULTIVECTOR = int(os.getenv("SIEM_CORR_MULTIVECTOR", 3))  # 다중 벡터 최소 종류
    SIEM_CORR_BRUTE = int(os.getenv("SIEM_CORR_BRUTE", 5))              # 지속 브루트포스 최소 횟수
    SIEM_CORR_DISTRIBUTED = int(os.getenv("SIEM_CORR_DISTRIBUTED", 6))  # 분산 공격 최소 출발지 수
    # 수집 offset 영속화 — 없으면 재시작마다 로그 전체를 재처리한다
    SIEM_STATE_PATH = os.getenv("SIEM_STATE_PATH", "data/siem_offsets.json")
    # HIGH/CRITICAL 외부 프로브를 알림으로 승격할지 (자동차단 경로는 열리지 않음)
    SIEM_PROMOTE_ALERTS = os.getenv("SIEM_PROMOTE_ALERTS", "True")

    # Syslog 수신 (원격 침해시도 수집) — KR/USA 등이 syslog 로 전송
    SYSLOG_ENABLED = os.getenv("SYSLOG_ENABLED", "True")   # 수신기 활성 여부
    SYSLOG_BIND = os.getenv("SYSLOG_BIND", "127.0.0.1")    # 바인드 주소(로컬만: 127.0.0.1)
    SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", 5514))       # 비특권 포트(514는 sudo 필요)
    SYSLOG_MAX_CONNS = int(os.getenv("SYSLOG_MAX_CONNS", 50))  # 동시 TCP 연결 상한

    # 허니팟 (유인 서비스로 침해시도 능동 포착)
    HONEYPOT_ENABLED = os.getenv("HONEYPOT_ENABLED", "True")
    HONEYPOT_BIND = os.getenv("HONEYPOT_BIND", "127.0.0.1")   # 실포착은 0.0.0.0+외부노출
    HONEYPOT_PORTS = os.getenv("HONEYPOT_PORTS", "")           # "2222,2323,3306,6379,8081,9200"
    HONEYPOT_COOLDOWN = float(os.getenv("HONEYPOT_COOLDOWN", 30))  # 동일 IP 재알림 간격(초)
    # 동시 처리 상한 — 외부 노출(0.0.0.0) 시 스레드 고갈 방지. 초과분은 접촉만 기록 후 즉시 차단
    HONEYPOT_MAX_CONNS = int(os.getenv("HONEYPOT_MAX_CONNS", 200))

    # SSH 인증 로그 실시간 탐지
    AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
    SSH_BRUTE_THRESHOLD = int(os.getenv("SSH_BRUTE_THRESHOLD", 5))   # 실패 횟수
    SSH_BRUTE_WINDOW = float(os.getenv("SSH_BRUTE_WINDOW", 120))      # 집계 구간(초)

    # IP 평판 조회 (AbuseIPDB) — 공격 IP 실제 위험도로 정탐/오탐 근거 강화
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")   # 없으면 데모 점수 fallback
    ABUSEIPDB_CACHE_HOURS = float(os.getenv("ABUSEIPDB_CACHE_HOURS", 6))
    ABUSEIPDB_MIN_SCORE = int(os.getenv("ABUSEIPDB_MIN_SCORE", 75))  # 이 점수↑ = 악성

    # VirusTotal v3 — 파일 업로드 없이 MD5/SHA1/SHA256 기존 리포트 조회
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_TIMEOUT = float(os.getenv("VIRUSTOTAL_TIMEOUT", 8))
    VIRUSTOTAL_CACHE_HOURS = float(os.getenv("VIRUSTOTAL_CACHE_HOURS", 6))

    # ── Claude API 호출 회복력 ──
    # SDK 기본은 타임아웃 10분 × 재시도 2회 = 최대 30분. 단일 워커 큐라
    # 한 번 막히면 그만큼 트리아지 전체가 정체된다(AUDIT B-4).
    AI_TIMEOUT_SECONDS = float(os.getenv("AI_TIMEOUT_SECONDS", 30))
    AI_MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", 1))
    # 연속 실패가 이 횟수를 넘으면 아래 시간만큼 호출을 멈추고 규칙 기반으로 대체
    AI_BREAKER_THRESHOLD = int(os.getenv("AI_BREAKER_THRESHOLD", 3))
    AI_BREAKER_COOLDOWN = float(os.getenv("AI_BREAKER_COOLDOWN", 300))

    # EDR (엔드포인트 탐지·대응) — AI 기반 프로세스 행위 관제
    EDR_SCAN_INTERVAL = float(os.getenv("EDR_SCAN_INTERVAL", 5))
    EDR_RESPONSE_MODE = os.getenv("EDR_RESPONSE_MODE", "simulate")  # simulate | kill
    EDR_HOST_LABEL = os.getenv("EDR_HOST_LABEL", "")

    # 네트워크 모니터링 관제
    NET_MONITOR_INTERVAL = float(os.getenv("NET_MONITOR_INTERVAL", 5))
    # 감시 대상 서비스: "이름=host:port;이름2=host:port" (비우면 대시보드 자체만 점검)
    NET_MONITOR_TARGETS = os.getenv("NET_MONITOR_TARGETS", "")

    # Sigma 룰 엔진 (업계 표준 탐지룰)
    SIGMA_RULES_DIR = os.getenv("SIGMA_RULES_DIR", "data/sigma")
    # YARA 파일 스캐너 — 해시 대조가 못 잡는 변종을 내용 패턴으로 잡는다
    YARA_ENABLED = os.getenv("YARA_ENABLED", "True") == "True"
    YARA_RULES_DIR = os.getenv("YARA_RULES_DIR", "data/yara")
    YARA_MAX_FILE_MB = float(os.getenv("YARA_MAX_FILE_MB", 32))
    YARA_TIMEOUT = int(os.getenv("YARA_TIMEOUT", 10))
    YARA_MAX_FILES = int(os.getenv("YARA_MAX_FILES", 2000))
    # 자동 스캔: EDR 이 관측한 프로세스의 실행 파일 + 지정 디렉터리 감시
    YARA_SCAN_PROCESSES = os.getenv("YARA_SCAN_PROCESSES", "True") == "True"
    YARA_WATCH_DIRS = os.getenv("YARA_WATCH_DIRS", "")   # "경로1,경로2" (비우면 감시 안 함)
    YARA_WATCH_INTERVAL = float(os.getenv("YARA_WATCH_INTERVAL", 30))
    YARA_SEEN_CACHE = int(os.getenv("YARA_SEEN_CACHE", 20000))

    # 일일 AI 리포트
    REPORT_HOUR = int(os.getenv("REPORT_HOUR", 8))     # 매일 자동 생성 시각(0~23)
    REPORT_DIR = os.getenv("REPORT_DIR", "data/reports")

    # ── 로깅 (modules/logging_setup.py) ──
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")          # DEBUG|INFO|WARNING|ERROR
    LOG_DIR = os.getenv("LOG_DIR", "logs")              # 회전 로그 파일 위치
    LOG_FILE = os.getenv("LOG_FILE", "soc.log")
    LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", 5 * 1024 * 1024))
    LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", 5))

    # 알림 보존·아카이브
    ALERT_RETENTION_DAYS = int(os.getenv("ALERT_RETENTION_DAYS", 90))  # N일 경과분 아카이브
    ALERT_ARCHIVE_RETENTION_DAYS = int(os.getenv("ALERT_ARCHIVE_RETENTION_DAYS", 365))
    AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", 365))
    # DB 경로 — wiring.py 가 읽고 있었으나 여기 없어 .env 로 바꿀 수 없었다
    AUDIT_DB = os.getenv("AUDIT_DB", "data/audit.db")
    WATCHLIST_DB = os.getenv("WATCHLIST_DB", "data/watchlist.db")
    # 위협 헌팅 콘솔 — 저장된 쿼리 (docs/AUDIT.md 3단계 제안 #7)
    HUNT_DB = os.getenv("HUNT_DB", "data/hunts.db")

    # 알림 중복제거·억제 레이어
    DEDUP_ENABLED = os.getenv("DEDUP_ENABLED", "True")
    DEDUP_WINDOW_SECONDS = float(os.getenv("DEDUP_WINDOW_SECONDS", 300))   # 병합 윈도우
    DEDUP_STORM_THRESHOLD = int(os.getenv("DEDUP_STORM_THRESHOLD", 20))    # 스톰 전환 횟수
    DEDUP_STORM_WINDOW_SECONDS = float(os.getenv("DEDUP_STORM_WINDOW_SECONDS", 60))
    DEDUP_STORM_SUMMARY_SECONDS = float(os.getenv("DEDUP_STORM_SUMMARY_SECONDS", 300))
    # 최초 1회 시드용 억제 규칙 "이름=유형:출발지접두:룰ID:사유; ..." (이후 DB/API 에서 편집)
    DEDUP_SUPPRESS_RULES = os.getenv("DEDUP_SUPPRESS_RULES", "")
    DEDUP_RETENTION_DAYS = int(os.getenv("DEDUP_RETENTION_DAYS", 90))

    # 인시던트 보존 — RESOLVED 만 대상. 진행 중 케이스는 대상 아님
    INCIDENT_RETENTION_DAYS = int(os.getenv("INCIDENT_RETENTION_DAYS", 365))
    # 차단 결정 재현 로그 (docs/AUDIT.md 3단계 제안 C)
    BLOCK_DECISION_DB = os.getenv("BLOCK_DECISION_DB", "data/block_decisions.db")
    BLOCK_DECISION_RETENTION_DAYS = int(os.getenv("BLOCK_DECISION_RETENTION_DAYS", 365))
    # 마지막 활동 후 이 기간 조용하면 자동 종료(RESOLVED). 0 이면 비활성.
    # 인시던트를 닫는 자동 경로가 없어 생성만 되고 닫히지 않던 문제 해소(AUDIT B-3a)
    INCIDENT_AUTO_RESOLVE_DAYS = int(os.getenv("INCIDENT_AUTO_RESOLVE_DAYS", 30))
    # SOAR 실행 이력 보존 — 종료된 것만. 승인 대기·진행 중은 대상 아님
    SOAR_EXECUTION_RETENTION_DAYS = int(os.getenv("SOAR_EXECUTION_RETENTION_DAYS", 90))

    # ML 트래픽 피처 보존 — 재학습 소스라 알림보다 길게 잡는다
    ML_FEATURE_RETENTION_DAYS = int(os.getenv("ML_FEATURE_RETENTION_DAYS", 180))

    # 파일 로그·리포트·생성 플레이북 보존 (DB 보존과 분리)
    DATA_RETENTION_DAYS = int(os.getenv("DATA_RETENTION_DAYS", 30))
    DATA_RETENTION_INTERVAL_HOURS = float(os.getenv("DATA_RETENTION_INTERVAL_HOURS", 6))

    # 자동화 취약점 패치 (Ansible)
    PATCH_APPLY_ENABLED = os.getenv("PATCH_APPLY_ENABLED", "False")  # 실제 적용 허용 여부
    PATCH_PLAYBOOK_DIR = os.getenv("PATCH_PLAYBOOK_DIR", "data/ansible")
    # 원격 실행 허용 명령 (쉼표 구분). 비우면 조회 전용 기본 목록을 쓴다.
    PATCH_COMMAND_ALLOWLIST = os.getenv("PATCH_COMMAND_ALLOWLIST", "")
    ANSIBLE_TARGETS = os.getenv("ANSIBLE_TARGETS", "")  # 일괄 명령/패치 원격 대상 "이름=user@host;..."

    # 취약점 스캐너 (포트/서비스/CVE) — 대상은 ANSIBLE_TARGETS 공유
    VULN_SCAN_PORTS = os.getenv("VULN_SCAN_PORTS", "")  # "22,80,443" (비우면 기본 포트셋)

    # 웹 엔드포인트 퍼저 (견고성 점검) — 본인 소유 서버만
    FUZZ_TARGETS = os.getenv("FUZZ_TARGETS", "")          # "이름=host:port;..." (비우면 NET_MONITOR_TARGETS)
    FUZZ_RATE = float(os.getenv("FUZZ_RATE", 5))          # req/s (부하 억제)
    FUZZ_MAX_REQUESTS = int(os.getenv("FUZZ_MAX_REQUESTS", 300))
    FUZZ_TIMEOUT = float(os.getenv("FUZZ_TIMEOUT", 5))
    FUZZ_ALLOW_WRITE = os.getenv("FUZZ_ALLOW_WRITE", "False")  # POST 등 쓰기 메서드 허용 여부

    # 푸시 알림 (ntfy) — 정탐/CRITICAL만 폰으로
    NTFY_ENABLED = os.getenv("NTFY_ENABLED", "False")
    NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh")
    NTFY_TOPIC = os.getenv("NTFY_TOPIC", "")          # 폰 ntfy 앱에서 구독할 토픽
    NTFY_TOKEN = os.getenv("NTFY_TOKEN", "")          # 인증 서버용(선택)
    NTFY_MIN_SEVERITY = os.getenv("NTFY_MIN_SEVERITY", "CRITICAL")
    NTFY_COOLDOWN = float(os.getenv("NTFY_COOLDOWN", 300))

    # SOAR 자동 대응 설정
    SOAR_BLOCK_MODE = os.getenv("SOAR_BLOCK_MODE", "simulate")  # simulate | ufw | iptables
    SOAR_AUTO_BLOCK = os.getenv("SOAR_AUTO_BLOCK", "True")
    SOAR_APPROVAL_REQUIRED = os.getenv("SOAR_APPROVAL_REQUIRED", "True") == "True"
    SOAR_APPROVAL_TIMEOUT_MINUTES = int(os.getenv("SOAR_APPROVAL_TIMEOUT_MINUTES", 15))
    SOAR_MIN_BLOCK_CONFIDENCE = int(os.getenv("SOAR_MIN_BLOCK_CONFIDENCE", 95))
    SOAR_REQUIRE_CORROBORATION = os.getenv("SOAR_REQUIRE_CORROBORATION", "True") == "True"
    INCIDENT_SAVE_DEBOUNCE_SECONDS = float(os.getenv("INCIDENT_SAVE_DEBOUNCE_SECONDS", 5))
    # 차단 자동 만료 (시간) — 0 이면 영구 차단
    SOAR_BLOCK_TTL_HOURS = float(os.getenv("SOAR_BLOCK_TTL_HOURS", 24))
    # 절대 차단 금지 IP/대역 (쉼표 구분, 대역은 "1.2.3." 형태 접두). 사설·Tailscale은 자동 보호
    SOAR_BLOCK_ALLOWLIST = os.getenv("SOAR_BLOCK_ALLOWLIST", "")
    SOAR_FIREWALL_HELPER = os.getenv("SOAR_FIREWALL_HELPER", "/usr/local/sbin/soc-ufw")

    # ── 대시보드 인증 ──
    AUTH_ENABLED = os.getenv("AUTH_ENABLED", "True") == "True"
    DASH_USERNAME = os.getenv("DASH_USERNAME", "admin")
    DASH_PASSWORD = os.getenv("DASH_PASSWORD", "")            # 평문(편의) — 시작 시 해시로 변환
    DASH_PASSWORD_HASH = os.getenv("DASH_PASSWORD_HASH", "")  # pbkdf2 해시(권장)
    SESSION_HOURS = float(os.getenv("SESSION_HOURS", 12))     # 로그인 세션 유지 시간
    # 세션 쿠키 보안 (Tailscale는 HTTP라 Secure 플래그는 기본 off)
    SESSION_COOKIE_HTTPONLY = True
    # Strict: 외부 사이트에서 시작된 요청에는 쿠키를 아예 붙이지 않는다(CSRF 1차 방어).
    # Lax 는 top-level GET 에 쿠키를 붙여 주므로 링크 클릭 시 로그인 상태가 유지되지만,
    # 이 대시보드는 북마크/직접 접속으로 쓰므로 Strict 로 얻는 방어가 더 크다.
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Strict")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False") == "True"

    # ── CORS ──
    # 이 대시보드는 자기 페이지가 자기 API 를 부르는 동일 출처 앱이라 CORS 가 필요 없다.
    # 예전에는 CORS(app, supports_credentials=True) 로 열려 있었는데, flask-cors 는
    # origins 미지정 + credentials 조합에서 **요청의 Origin 을 그대로 반사**한다.
    # 그 결과 로그인 상태의 분석가가 임의 사이트를 방문하면 그 사이트 스크립트가
    # 세션 쿠키를 실어 API 전체를 호출하고 응답을 읽을 수 있었다(docs/AUDIT.md C-1).
    # 별도 출처 클라이언트가 필요할 때만 쉼표로 구분해 명시한다.
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "")

    # ── 보안 헤더 ──
    SECURITY_HEADERS_ENABLED = os.getenv("SECURITY_HEADERS_ENABLED", "True") == "True"
    # CSP 를 차단 대신 보고 전용으로 (새 CDN 추가 시 영향 확인용)
    CSP_REPORT_ONLY = os.getenv("CSP_REPORT_ONLY", "False") == "True"
    # 추가 허용 출처 (공백 구분) — 새 CDN·폰트 호스트를 붙일 때
    CSP_EXTRA_SOURCES = os.getenv("CSP_EXTRA_SOURCES", "")

    # ── CSRF ──
    # 상태변경 요청(POST/PUT/DELETE/PATCH)의 Origin/Referer 가 자기 호스트인지 검증한다.
    # 프론트 35개 fetch 호출부를 건드리지 않고 적용되는 표준 방어다(OWASP 권고).
    CSRF_PROTECTION = os.getenv("CSRF_PROTECTION", "True") == "True"
    # 대시보드를 여러 주소로 접속한다면(예: Tailscale IP + 호스트명) 여기에 추가
    CSRF_TRUSTED_ORIGINS = os.getenv("CSRF_TRUSTED_ORIGINS", "")

    # Demo mode (use simulated data when real sources unavailable)
    DEMO_MODE = os.getenv("DEMO_MODE", "True") == "True"
    DEMO_UPDATE_INTERVAL = float(os.getenv("DEMO_UPDATE_INTERVAL", 2.0))
