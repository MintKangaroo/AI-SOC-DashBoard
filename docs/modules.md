# 모듈 상세 설명

모든 모듈은 `modules/` 아래 있으며 `start()` / `stop()` / `get_*()` 인터페이스와 **데모 fallback**을 갖는다.
SocketIO emit은 `deque`·`Lock`으로 스레드 안전하게 처리한다.

## ① 수집 · SIEM

| 모듈 | 클래스 | 역할 | 핵심 이벤트/API |
|------|--------|------|-----------------|
| `packet_analyzer` | PacketAnalyzer | PyShark/Scapy 패킷 캡처, pps/bps·Top Talkers 통계 | `packet_update` |
| `sysmon_parser` | SysmonParser | Windows Sysmon 이벤트 파싱, Metasploit 탐지 | `sysmon_update` · `sysmon_alert` |
| `access_log_parser` | AccessLogCollector | 자동매매 봇 access log 수집·정규화, 침해 프로브 분류 | `classify_request()` |
| `authlog_parser` | AuthLogMonitor | `/var/log/auth.log` tail, SSH 브루트포스 탐지 | `report_alert("BRUTE_FORCE")` |
| `net_monitor` | NetworkMonitor | psutil 활성 연결·리스닝 포트·대역폭, 서비스 헬스체크 | `net_event` · `net_status` |
| `syslog_receiver` | SyslogReceiver | RFC3164/5424 수신(UDP+TCP 5514) — KR/USA 원격 침해시도 수집 | `syslog_event` |
| `honeypot` | Honeypot | 유인 서비스 리스너(SSH/Telnet/Redis 등). 접촉 자체가 고신뢰 침해지표 | `honeypot_hit` |
| `snort_monitor` | SnortMonitor | Snort fast-alert tail, SID별 정·오탐 품질 집계 | `/api/integrations/snort` |

## ② 탐지 · Detection Engineering

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `threat_detector` | ThreatDetector | DDoS·포트스캔·C2 탐지, **신뢰도 스코어링**, Alert 관리 | `_confidence()` · `analyze_packet()` · `report_alert()` |
| `sigma_engine` | SigmaEngine | Sigma 표준 룰 로드·평가(field 수정자·condition 파서) | `sigma_match`, 룰 파일 추가로 확장 |
| `edr` | EDRSensor | psutil 프로세스 IOA(리버스셸·웹셸·마이너·스캐너), 안전 종료 | `edr_detection` · `kill_process()`(simulate 기본) |
| `hash_checker` | HashChecker | MD5/SHA256 악성 DB 대조, EICAR | `scan_file()` |
| `mitre_attack` | MitreTracker | 위협·Sysmon → 14 Tactic × Technique 매핑 | `map_threat()` · `mitre_hit` |
| `yara_scanner` | YaraScanner | **파일 내용 기반** 악성코드 탐지. 해시가 못 잡는 변종을 덮는다. EDR 실행파일 자동스캔 + 디렉터리 감시 | `scan_file()` · `yara_match` |
| `coverage` | — | 탐지 커버리지 자가 진단 — 룰·퍼플팀검증·히트 3축을 조인해 **무엇을 못 잡는지** 답한다 | `build_coverage()` |
| `siem_correlation` | SIEMCorrelator | 다중 벡터·지속 브루트포스·분산 공격을 상관 규칙으로 승격 | `R-*` 규칙 |

> **detection-as-code**: Sigma·YARA 룰은 각각 정탐/오탐 샘플을 함께 들고 다니고
> CI 가 매 push 마다 검증한다. 자세한 건 [detection_rules.md](detection_rules.md).


## ③ 위협 인텔 · 분석

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `ip_reputation` | IPReputation | AbuseIPDB 조회(캐시·데모 fallback), 정탐 근거 강화 | `check(ip)`, 사설/자기IP 제외 |
| `threat_intel` | ThreatIntel | 악성 IP/URL 피드 관리·매칭 | `_parse_ip_list()` |
| `watchlist` | Watchlist | IOC(IP/도메인/해시) 워치리스트, 알림 대조 히트 집계(능동 헌팅) | `match_alert()` · `watchlist_hit` |
| `correlation` | — | 같은 출발지 알림을 시간 윈도우로 묶어 MITRE 전술 순서 캠페인 구성 | `build_campaigns()` · `compute()` |
| `ml_analyst` | MLAnalyst | Isolation Forest 이상탐지(참고용, 탐지 경로 미연결) | `ml_analysis` |
| `ml_feature_store` | MLFeatureStore | 트래픽 피처 영속화 — 재학습·평가의 전제 | — |
| `alert_dedup` | AlertDeduplicator | 핑거프린트 중복 병합·규칙 억제·스톰 요약 | `alert_dedup` |
| `ai_analyst` | AIAnalyst | Claude 비동기 분석 큐·대응 권고·챗봇·리포트 텍스트 | `ai_analysis` · `generate_text()` |
| `decision_support` | DecisionSupport | 위협 그룹핑 + 정오탐 학습 prior | `get_recommendations()` |

## ④ 대응 · SOAR

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `soar` | SOAREngine | AI 트리아지(정탐 에스컬레이션/오탐 종결), 자동 차단, TTL·allowlist | `soar_action`, `_is_blockable()` 안전장치 |
| `incidents` | IncidentManager | 알림 케이스화·상태 추적 | `get_incidents()` |
| `notifier` | Notifier | ntfy 푸시(정탐·차단만, 쿨다운) | `notify_true_positive()` · `notify_block()` |
| `daily_report` | DailyReport | 전 모듈 지표 집계 → Claude 브리핑(규칙 fallback) | `report_status` |

| `block_decision` | BlockDecisionLog | 차단 결정 재현 — 게이트 판정이 곧 실제 차단 결정. **차단 안 한 건도 기록**, 임계값 replay | `evaluate_gates()` · `replay()` |
| `playbooks` | — | SOAR 플레이북 정의(단계·조건) |
| `soar_execution_store` | SOARExecutionStore | 플레이북 실행 이력 영속화(재시작 후 복원) |
| `virustotal` | VirusTotalClient | 해시 평판 조회(파일 업로드 없음), 캐시·재시도 |

## ⑤ 취약점 관리 · 검증

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `vuln_scanner` | VulnScanner | 포트·서비스·CVE 스캔(nmap/vulners·소켓), **apt 교차검증** | `vulnscan_host`, `_cross_validate()`, 원격은 ansible |
| `web_fuzzer` | WebFuzzer | 엔드포인트 견고성 퍼징(5xx·행·입력반사) | `fuzz_finding`, 사설 대상만·GET 전용·rate-limit |
| `patch_manager` | PatchManager | 다중 서버 Ansible 일괄 명령/패치, dry-run 기본 | `patch_job`, 파괴적 명령 blocklist |
| `purple_team` | PurpleTeam | 7종 모의공격을 실제 탐지엔진에 주입해 커버리지 검증 | `run_all()`, RFC5737 TEST-NET 출발지 |

## ⑥ SOC 운영 · 거버넌스

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `soc_metrics` | — | MTTR/MTTA·오탐율·종결율·일별추세·요일×시간 히트맵·TOP 위협/공격자 | `compute(store, incidents, soar_stats, days)` |
| `audit_log` | AuditLog | 알림 ACK/종료·SOAR 차단·인시던트 변경을 append-only 기록 | `record(actor, action, target)` · `search()` |
| `system_health` | — | 전 모듈 상태(real/demo/off/live/down) 중앙 방어적 집계 | `collect(app)`, `SPECS` 리스트 |
| `telemetry` | Telemetry | **자기 관측성** — 지점별 지연 p50/p95·실패·큐 적체. `system_health` 가 '살아 있는가'라면 여기는 '얼마나 느린가' | `timed()` · `register_probe()` |
| `hunt` | HuntStore | 위협 헌팅 저장 쿼리 — 재실행·**지난 실행 이후 델타**·워치리스트 승격 | `run()` · `promote_to_watchlist()` |
| `ocsf_export` | — | 알림 → OCSF 1.1.0 Detection Finding 변환(내보내기 전용) | `alert_to_ocsf()` |
| `retention` | — | 계층별 보존 정책 실행(알림·아카이브·감사·파일·인시던트·SOAR·결정기록) | `run_cleanup()` · `preview()` |
| `logging_setup` | — | 구조화 로깅 설정. **모든 모듈이 `_log = get_logger(__name__)`** 를 쓴다(print 금지) | `configure_logging()` |

## 플랫폼

| 모듈 | 클래스 | 역할 |
|------|--------|------|
| `auth` | AuthManager | 로그인(pbkdf2), IP별 브루트포스 락아웃, 세션 |
| `geoip` | AttackMapTracker | GeoIP 조회, 공격 지도 스트림(`map_attack`) |
| `alert_store` | AlertStore | 알림 영속화(alerts.db)·전체 이력 검색·집계·보존/아카이브(무손실 `alerts_archive`) |
| `system_info` | — | 호스트/인터페이스 정보 |

> 서비스 생성·교차배선·시작은 `app.py`가 아니라 **`wiring.py`**(`build_services` / `start_services`)에서 처리한다.
> API는 도메인별로 분리돼 있고(`api/{detection,analysis,monitoring,scan,response}_routes.py`) 모두 `api/_common.py`의 `api_bp`를 공유한다.

## 확장 방법 (새 시스템 연동)

1. `modules/` 에 새 파서 모듈 추가 — `start()`·`stop()`·`get_*()` 구현 + 데모 fallback
2. `wiring.build_services()` 에서 초기화 후 `app.<name>` 등록, `wiring.start_services()` 에서 `<name>.start(demo=demo)` 호출
3. 알맞은 `api/{도메인}_routes.py` 에 `/api/...` 엔드포인트 추가 (`from api._common import api_bp, threat_detector` 등 **이름 접근자** — 위치 언패킹 금지)
4. `templates/panels/<name>.html` 패널 추가 + `dashboard.html` 에 `{% include %}` 및 사이드바 링크
5. `static/js/dash/*.js` 에 `socket.on(...)` 수신 + 렌더 함수, `showPanel()` 훅에 `load<Name>()` 배선(스크립트 태그 등록)
   — 파일 전체를 **IIFE** 로 감싸고 밖에서 부를 이름만 파일 끝 `Object.assign(window, {...})` 에 넣는다.
     인라인 `onclick` 이 부르는 함수도 반드시 여기 넣어야 한다(안 넣으면 클릭이 조용히 죽는다 — 테스트가 잡는다)
6. 모듈 헬스에 표시하려면 `system_health.SPECS` 에 `(key, label, category)` 한 줄 추가
7. `tests/` 에 파싱·판정·안전장치 단위 테스트 추가 (네트워크·외부실행 없이)
