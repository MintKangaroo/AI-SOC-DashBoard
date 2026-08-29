# CLAUDE.md — SOC 대시보드 프로젝트 컨텍스트

## 프로젝트 개요

Flask 기반 실시간 보안관제(SOC) 대시보드.  
Claude AI(claude-sonnet-4-6)를 통합하여 보안 이벤트를 자동 분석하고 대응 권고를 제공합니다.

## 기술 스택

- **백엔드**: Flask 3.x, Flask-SocketIO (threading 모드), Flask-CORS
- **AI**: Anthropic SDK (claude-sonnet-4-6), 비동기 큐 기반 분석
- **패킷 분석**: PyShark (캡처), Scapy (패킷 조작), 데모 fallback 포함
- **로그 분석**: win32evtlog (Sysmon), 데모 fallback 포함
- **해시**: hashlib (MD5, SHA1, SHA256, SHA512)
- **지도**: Leaflet.js + ip-api.com GeoIP
- **프론트**: Bootstrap 5, Chart.js, DataTables, Socket.IO

## 코드 작성 규칙

- 모든 모듈은 **데모 fallback** 필수 — 실제 환경(Npcap, Sysmon 등) 없이도 실행 가능해야 함
- SocketIO emit은 항상 **threading-safe** (deque, Lock 사용)
- 각 모듈은 독립적: `start()` / `stop()` / `get_*()` 인터페이스 유지
- 외부 시스템 연동 패널은 `/api/integrations/{system}` 엔드포인트 규칙 따름
- 프론트엔드 차트 갱신은 `animation: false` — 실시간 성능 우선

## 주요 파일

| 파일 | 역할 |
|------|------|
| `app.py` | Flask 앱 팩토리, 서비스 초기화, SocketIO 이벤트 |
| `config.py` | 환경변수 기반 설정 (python-dotenv) |
| `modules/packet_analyzer.py` | PyShark/Scapy 패킷 캡처, 통계, SocketIO emit |
| `modules/threat_detector.py` | DDoS/포트스캔/악성코드 탐지, Alert 객체 관리 |
| `modules/hash_checker.py` | 해시 계산 + 악성 DB 비교 |
| `modules/yara_scanner.py` | YARA 내용 기반 악성코드 탐지 — 해시가 못 잡는 변종. 룰은 `data/yara/*.yar`, 정탐/오탐 샘플은 `rule_tests.yml` 에 두고 CI 가 검증. EDR 실행파일 자동스캔 + 디렉터리 감시(지문 캐시로 중복 방지) |
| `modules/sysmon_parser.py` | Windows Sysmon 이벤트 파싱 |
| `modules/ai_analyst.py` | Claude API 연동, 비동기 분석 큐, 챗봇 |
| `modules/ml_analyst.py` | 자체 이상탐지(Isolation Forest) — 참고용 판정, 탐지 경로 미연결 |
| `modules/ml_feature_store.py` | 트래픽 피처 영속화(ml_features.db) — 재학습·평가의 전제 |
| `experimental/` | 격리된 미검증 모델(RF·LSTM·Q-Learning) — 제품 코드가 import 하지 않음 |
| `modules/mitre_attack.py` | MITRE ATT&CK 14 Tactic × Technique 매핑 및 카운트 |
| `modules/coverage.py` | 탐지 커버리지 자가 진단 — 룰·퍼플팀검증·히트 3축 조인, 공백=다음에 쓸 룰 |
| `modules/block_decision.py` | 차단 결정 재현 로그 — 게이트 판정(`evaluate_gates`)이 곧 실제 차단 결정. 차단 안 한 건도 기록, 임계값 replay |
| `data/sigma/*.yml` | Sigma 탐지 룰. **각 룰은 `tests:` 블록에 positive/negative 샘플을 함께 담는다** — CI 가 강제 |
| `modules/geoip.py` | 공격 IP GeoIP 조회, 공격 지도 스트림 |
| `modules/syslog_receiver.py` | Syslog(UDP+TCP 5514) 수신 — KR/USA 원격 침해시도 수집 |
| `modules/honeypot.py` | 유인 서비스 리스너(SSH/Telnet/Redis 등) — 접촉=고신뢰 침해지표 |
| `modules/alert_store.py` | 알림 영속화(alerts.db) — 검색/집계/보존/아카이브. 조회는 `scope`(all/live/archive)로 활성+아카이브 통합 |
| `modules/alert_dedup.py` | 중복제거·억제 레이어 — 핑거프린트 병합·규칙 억제·스톰 요약 |
| `modules/soc_metrics.py` | SOC 운영 지표(MTTR/MTTA/오탐율/히트맵/TOP) 집계 |
| `modules/audit_log.py` | 전역 감사 로그(append-only audit.db) |
| `modules/watchlist.py` | IOC 워치리스트(watchlist.db) — 능동 헌팅 매칭 |
| `modules/correlation.py` | 킬체인 상관관계 — 같은 IP를 MITRE 전술 순서 캠페인으로 구성 |
| `modules/system_health.py` | 전 모듈 헬스 중앙 집계(방어적 조회, SPECS 리스트) |
| `modules/telemetry.py` | 자기 관측성 — 지점별 지연 p50/p95·실패·큐 적체. `with telemetry.timed("지점")` 로 계측, 프로브는 모듈 수정 없이 등록 |
| `modules/logging_setup.py` | 구조화 로깅 설정 — 모든 모듈이 `_log = get_logger(__name__)` 사용 (print 금지) |
| `app.py` | Flask 앱 팩토리, SocketIO 이벤트 (서비스 생성/시작은 `wiring.py`) |
| `wiring.py` | 서비스 생성·교차배선·시작 (`build_services` / `start_services`) |
| `api/routes.py` | API 라우트 집계자 (도메인 파일 임포트만) |
| `api/_common.py` | 공용 헬퍼 (`api_bp`, `get_services`, `_mitre`, `_actor`, `audit_record`) |
| `api/{detection,analysis,monitoring,scan,response}_routes.py` | 도메인별 REST 엔드포인트 (모두 `api_bp` 공유) |
| `templates/dashboard.html` | 레이아웃·사이드바 (패널은 `templates/panels/*.html` include) |
| `templates/panels/*.html` | 패널별 UI 조각 (Jinja include, 34개) |
| `static/js/dash/01~19-*.js` | 패널별 JS (원본 순서대로 `<script>` 로드). 각 파일은 IIFE — 공개 이름만 파일 끝 `Object.assign(window, {...})` 에 명시 |
| `static/vendor/` | 자체 호스팅 프런트 라이브러리 (CDN 미사용 — 격리망 동작·CSP `'self'`) |

## 외부 시스템 연동 확장 방법

새 시스템(예: 방화벽) 연동 시:

1. `modules/` 에 새 파서 모듈 추가 (`start()`, `stop()`, `get_events()` 구현)
2. `wiring.py` 의 `build_services()` 에서 서비스 생성 + `app.{name}` 등록, `start_services()` 에 `.start()` 추가
3. 알맞은 `api/{도메인}_routes.py` 에 `/api/integrations/{name}` 엔드포인트 추가 (`from api._common import api_bp, get_services`)
4. `templates/panels/{name}.html` 패널 추가 + `dashboard.html` 에 `{% include %}` 및 사이드바 링크
5. `static/js/dash/` 에 패널 JS 추가(스크립트 태그 등록) + `showPanel()` 훅에 `load{Name}()` 연결
   — 파일 전체를 `(function () { ... })();` 로 감싸고, 밖에서 부를 이름만 파일 끝
     `Object.assign(window, { load{Name} })` 에 넣는다. **인라인 `onclick` 이 부르는 함수도
     반드시 여기 넣어야 한다** (안 넣으면 클릭이 조용히 죽는다 — 테스트가 잡는다)
6. 모듈 헬스에 표시하려면 `modules/system_health.py` 의 `SPECS` 에 한 줄 추가

## AI 분석 흐름

```
위협 탐지 → Alert 생성 → SocketIO emit("new_alert")
  → 서버 SOAR가 CRITICAL/HIGH AI 트리아지를 1회 수행(브라우저 중복 요청 금지)
  → ai_analyst._do_analyze_alert() → Claude API 호출
  → SocketIO emit("ai_analysis") → UI 업데이트
```

## YARA 악성코드 탐지 흐름

```
수동:   /api/yara/scan (경로) → HASH_SCAN_ALLOWED_DIRS 검사 → scan_file/scan_directory
자동①: EDR _scan_loop → yara.scan_process_images(procs) → 실행 파일 내용 검사
        (Sigma 는 '무엇을 실행했나', YARA 는 '그 파일이 무엇인가')
자동②: YARA_WATCH_DIRS 감시 스레드 → 새/변경 파일만 scan_once()
  → 매치 시 report_alert("MALWARE_FILE") → AI 트리아지 → SOAR (+ MITRE)
  → emit("yara_match") → 패널·라이브 스트림
```
※ `scan_once()` 는 (경로+크기+mtime) 지문 캐시로 **같은 파일을 두 번 읽지 않는다.**
   EDR 이 수 초마다 같은 프로세스를 돌려주므로 캐시가 없으면 /usr/bin/python3 를
   하루에 수만 번 읽는다. 내용이 바뀌면 mtime 이 달라져 다시 스캔된다.
※ 자동 스캔은 `HASH_SCAN_ALLOWED_DIRS` 를 적용하지 않는다 — 그 제한은 **API 로
   들어오는 임의 경로**를 막기 위한 것이고, 프로세스 실행 파일은 /usr/bin 에 있다.
   비용은 파일 크기 상한·타임아웃·지문 캐시로 통제한다.
※ 심볼릭 링크는 따라가지 않는다(경로 탈출 방지). 매치 결과에 원문 페이로드를
   담지 않는다(패턴 식별자와 개수만).
※ **권한 없는 파일은 오류가 아니라 건너뜀이다**(`skipped_no_permission`).
   /etc 를 훑으면 shadow·sudoers 등 26건이 걸리는데, 이걸 오류로 세면 로그가
   잠기고 텔레메트리의 실패 카운터가 거짓말을 한다.
※ 룰이 자동 스캔에 쓰이면 오탐 기준이 달라진다 — 시스템 파일 전체를 훑기
   때문이다. `test_system_files_do_not_false_positive` 가 /usr/bin·/usr/sbin·/bin
   을 실제로 스캔한다. **이게 실패하면 진짜 오탐을 찾은 것이니 그냥 넘기지 말 것.**

## 자체 ML 분석 흐름

```
packet_analyzer.get_stats() → ml_analyst.feed_traffic() (3초 주기)
  ├→ ml_feature_store.record()  → data/ml_features.db (append-only, real/demo 구분)
  └→ _run_models(): Isolation Forest
     → SocketIO emit("ml_analysis") → ML 패널 차트 갱신

※ ML 판정은 참고용이다(summary.advisory_only=true). threat_detector·soar 의
   탐지·차단 결정에 연결되어 있지 않다.
※ RF·LSTM·Q-Learning 은 실데이터 미학습·출력 미사용으로 experimental/ 에 격리.
   격리 사유와 복귀 조건은 experimental/README.md 참조.
※ 성능 수치는 scripts/eval_ml.py 가 출력한 값으로만 주장한다. 현재는 실트래픽
   피처와 사람 라벨이 부족해 '측정 불가'이며, 부족분은 docs/ml_models.md 에 기록.
```

## 알림 중복제거·억제 흐름

```
report_alert() / analyze_packet() → Alert → _add_alert()
  → alert_dedup.evaluate(alert)
     ├ suppress  : 운영자 규칙 매치 → 실시간 표시 억제 (CRITICAL 은 면제)
     ├ duplicate : 윈도우 내 동일 핑거프린트 → 기존 알림 count/last_seen 증가
     │             emit("alert_dedup") → ×N 뱃지 갱신 (새 알림 생성 안 함)
     ├ storm     : 동일 핑거프린트 급증 → 요약 알림 1건 발행 후 카운트만
     └ pass      : 신규 → 기존 파이프라인(저장·emit·SOAR·MITRE) 진행
```
핑거프린트 = sha1(룰ID ‖ 유형 ‖ 출발지 ‖ 목적지 ‖ 정규화된 설명).
룰ID 는 소스별로 details 의 다른 키(rule_id/sid/rule/category/service)에 있어
`extract_rule_id()` 가 흡수한다. src_ip 는 IP 가 아닐 수 있다(SIGMA_MATCH=None,
EDR_THREAT=호스트명 — 실측 26%).

※ **어떤 알림도 조용히 사라지지 않는다.** 병합·억제된 이벤트는 전부
   `data/alert_dedup.db` 의 `suppressed_events` 에 원문째 보관되고
   `/api/dedup/suppressed` 로 복구 조회한다. dedup 이 예외를 던지거나
   미설정이면 알림을 통과시킨다 — 중복이 나오는 편이 유실보다 안전하다.
※ dedup(카운트 병합)은 전 심각도 적용(정보 손실 0), suppression(운영자 규칙)만
   CRITICAL 을 면제한다. 억제 규칙은 하드코딩하지 않고 `suppression_rules` 에 둔다.
※ 실측: 아카이브 110,748건 리플레이 → 76,191건으로 **31.2% 감축**,
   병합분 34,557건 전량 복구 가능, 처리 5,231건/초.

## MITRE ATT&CK 매핑 흐름

```
threat_detector._add_alert()   → mitre_tracker.map_threat(threat_type, ...)
sysmon_parser._record_event()  → mitre_tracker.map_sysmon_event(event_id, ...)
  → hits[(tactic, technique)] += 1
  → SocketIO emit("mitre_hit") → 매트릭스 셀 실시간 강조(hit-low/med/high)
```

## Syslog 원격 수집 흐름 (KR/USA 침해시도)

```
KR/USA (logging.handlers.SysLogHandler → 127.0.0.1:5514 UDP/TCP)
  → syslog_receiver 수신 → RFC3164/5424 파싱 → classify_syslog()
    (werkzeug access 재사용 + 보안 키워드) → 의심+외부 IP면
  → threat_detector.report_alert(BRUTE_FORCE/WEB_ATTACK/PORT_SCAN/...)
    → 신뢰도 → AI 트리아지 → SOAR → 인시던트 (+ 공격지도 + MITRE)
  → SocketIO emit("syslog_event") → Syslog 패널 + 라이브 스트림
```
※ 파일 tail(access_log_parser)과 병행. tail 은 로그 경로 고정 시, syslog 는
   로그 위치가 바뀌어도 안 깨짐(USA 처럼 대시보드 재기동 시 경로 변동 대응).
※ KR/USA 전송단: 각 프로젝트 `dashboard/soc_syslog.py`(install_soc_syslog)를
   create_app 에서 호출 → Flask after_request 로 접속 로그를 5514 로 포워딩
   (로컬 정상요청 제외, 예외는 모두 삼켜 매매 대시보드 무영향). 각 프로젝트
   재기동해야 활성. 끄기: 해당 프로젝트 env SOC_SYSLOG_ENABLED=0.

## 허니팟 흐름 (유인 서비스)

```
공격자 ─TCP접속─▶ honeypot 유인 포트(SSH2222/Telnet2323/MySQL3306/Redis6379/…)
  → 가짜 배너 전송 → 입력(자격증명/명령) 수집 → emit("honeypot_hit")
  → 연결만=HIGH / 입력=CRITICAL, 외부 IP면 report_alert("HONEYPOT")
    → 신뢰도 → AI 트리아지 → SOAR 차단 (+ 공격지도 + MITRE). 내부 IP 억제.
```
※ 기본 127.0.0.1 바인드(안전). 실제 인터넷 공격 포착은 HONEYPOT_BIND=0.0.0.0 +
   외부 노출 필요. 포트 점유 시 해당 포트만 안전 skip.

## SOC 운영 기능 흐름 (감사·워치리스트·상관관계)

```
감사: 알림 ACK/종료·SOAR 차단·인시던트 변경 → api._common.audit_record(action, target)
      → audit_log.record(actor=session, ...) (append-only audit.db) → /api/audit 조회

워치리스트: 등록 IOC(IP/도메인/해시) → threat_detector._add_alert 대조훅
      → watchlist.match_alert() 히트 집계 + emit("watchlist_hit") + alert.details["watchlist"]

지표: alert_store.aggregate(days) + incidents 타임라인 → soc_metrics.compute()
      → MTTR/MTTA/오탐율/일별추세/요일×시간 히트맵/TOP → /api/metrics/soc

킬체인: alert_store.since(hours) → correlation.build_campaigns()
      → 같은 src_ip를 시간 윈도우로 묶고 MITRE 전술 순서 정렬 → /api/correlation/campaigns

보존: alert_store.archive_older_than(days) → alerts_archive 테이블로 무손실 이동
      (config ALERT_AUTO_ARCHIVE=True 시 start_services에서 자동)
      retention 루프(6시간)가 함께 처리: ML피처·억제이벤트 정리,
      인시던트 자동종료(30일 조용 → RESOLVED) 후 RESOLVED 365일 경과분 삭제,
      SOAR 실행 이력 종료분 90일 경과분 삭제.
      ※ 진행 중 인시던트와 waiting_approval 실행은 절대 삭제 대상이 아니다.

동시성: alerts/audit/watchlist DB 는 WAL + busy_timeout 10s. alert_store 는
      **조회 전용 커넥션(query_only)을 쓰기 커넥션과 분리**한다 — 집계가 쓰기 락을
      잡으면 탐지 경로의 save() 가 통째로 막힌다(실측 최대 34초). 단 아카이브 이동
      (`_copy_to_archive`)은 읽기 락도 함께 잡는다.
      ※ WAL 에서 SQLite 는 ATTACH 된 DB 간 커밋의 원자성을 보장하지 않는다. 그래서
        활성→아카이브 이동은 **복사를 커밋한 뒤 삭제를 커밋하는 2단계**다. 크래시 시
        최악이 '양쪽 중복'이 되고(유실 아님), 기동 시 `_recover_interrupted_archive()`
        가 정리한다. 이 순서를 한 트랜잭션으로 되돌리면 알림이 유실될 수 있다.

조회범위: alert_store 의 search/aggregate/since/grouped_recent/snort_sid_stats 는
      `scope` 를 받는다 — 기본 `all`(임시뷰 `alerts_all` = 활성 UNION 아카이브),
      `live`(활성만), `archive`(아카이브만). 결과 행의 `archived` 플래그로 출처를
      구분한다. 아카이브 이동은 **보관이지 삭제가 아니므로 조회에서 빠지지 않는다.**
      단 상태·판정 변경(update_status/set_verdict)은 활성 테이블에만 적용된다.
```

## 환경 변수 (.env)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `ANTHROPIC_API_KEY` | - | Claude AI API 키 |
| `DEMO_MODE` | True | 가상 데이터 사용 여부 |
| `CAPTURE_INTERFACE` | 자동 | 패킷 캡처 인터페이스 |
| `DDOS_PACKET_THRESHOLD` | 2000 | DDoS 탐지 임계값(pps, 3초 지속) |
| `PORT_SCAN_THRESHOLD` | 40 | 포트스캔 탐지 임계값(30초 내 고유 포트) |
| `ALERT_RETENTION_DAYS` | 90 | 알림 보존 기간(경과 시 아카이브 대상) |
| `ALERT_ARCHIVE_RETENTION_DAYS` | 365 | 아카이브 이동 후 영구삭제까지의 보존 기간 |
| `AUDIT_RETENTION_DAYS` | 365 | 감사 로그 보존 기간 |
| `DATA_RETENTION_DAYS` | 30 | 파일 로그·리포트·플레이북 보존 기간(DB 제외) |
| `VIRUSTOTAL_API_KEY` | - | 악성코드 플레이북의 MD5/SHA1/SHA256 평판 조회 |
| `SYSLOG_ENABLED` | True | Syslog 수신기 활성 여부 |
| `SYSLOG_BIND` | 127.0.0.1 | Syslog 수신 바인드 주소(로컬만 권장) |
| `SYSLOG_PORT` | 5514 | Syslog 수신 포트(514는 sudo 필요) |
| `HONEYPOT_ENABLED` | True | 허니팟 유인 서비스 활성 여부 |
| `HONEYPOT_BIND` | 127.0.0.1 | 허니팟 바인드(실포착은 0.0.0.0+외부노출) |
| `HONEYPOT_PORTS` | (기본셋) | 유인 포트 "2222,2323,3306,6379,8081,9200" |
| `HONEYPOT_COOLDOWN` | 30 | 동일 IP 재알림 최소 간격(초) |
| `DEDUP_ENABLED` | True | 알림 중복제거·억제 레이어 활성 |
| `DEDUP_WINDOW_SECONDS` | 300 | 중복 병합 윈도우(초). 실측 5분에서 30.4% 병합 |
| `DEDUP_STORM_THRESHOLD` | 20 | 60초 내 동일 핑거프린트 이 횟수 초과 시 스톰 |
| `DEDUP_SUPPRESS_RULES` | - | 최초 1회 시드 "이름=유형:출발지접두:룰ID:사유;..." |
| `DEDUP_RETENTION_DAYS` | 90 | 억제·병합 이벤트 보관 기간 |
