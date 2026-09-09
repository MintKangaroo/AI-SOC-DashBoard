# SOC Dashboard 인수인계

> 아래는 2026-07-20 스냅샷입니다. 현재 인계는 [docs/HANDOVER.md](docs/HANDOVER.md),
> 최신 역할/세션 통제는 [docs/ACCESS_CONTROL.md](docs/ACCESS_CONTROL.md)를 참고하세요.

최종 확인일: 2026-07-20 (Asia/Seoul)  
브랜치: `main`  
기준 커밋: `42eb987` (`docs: 포트폴리오에 Splunk SIEM 검색·상관관계·플레이북 시각화 반영`)

## 프로젝트 현황

Flask 및 Flask-SocketIO 기반 실시간 SOC 대시보드다. 패킷·Sysmon·Syslog·SSH 인증 로그·허니팟·EDR 이벤트를 수집하고, 위협 탐지부터 AI/ML 분석, MITRE ATT&CK 매핑, SIEM 상관관계, SOAR 대응, 인시던트와 감사 로그 관리까지 제공한다.

주요 구조와 개발 규칙은 `CLAUDE.md`에 정리되어 있다.

- 앱 팩토리와 인증, Socket.IO 이벤트: `app.py`
- 서비스 생성·상호 배선·시작: `wiring.py`
- REST API: `api/`
- 탐지·분석·대응 모듈: `modules/`
- 대시보드 UI: `templates/`, `static/js/dash/`, `static/css/`
- 설정: `config.py`, `.env.example`
- 테스트: `tests/`

## 현재 검증 상태

최근 추가 기능:

- 내부 자료 유출 대응 추가: 내부→비허용 외부 목적지 대량 전송과 DNS 터널링,
  수집·압축 후 유출을 SIEM `R-INTERNAL-EXFIL/R-STAGING-EXFIL`로 상관 분석한다.
  SOAR `PB-DATA-EXFIL`은 증거 보존·범위 산정·인시던트 생성까지만 자동 수행하고
  내부 호스트/계정 격리는 분석가 결정으로 남긴다.
- 실운영 전환: 로컬 `.env`는 `DEMO_MODE=False`. 알림에 origin과 분석가 확정
  판정(미판정/조사/정탐/오탐, 담당자·근거·시각)을 별도 저장한다.
- Snort SID별 확정 품질 통계 및 `SNORT_BLOCK_EXCLUDED_SIDS` 지원. 기본 SID 254는
  Tailscale DNS 오탐으로 표시만 하고 자동 차단 근거에서 제외한다.
- 인시던트 운영 저장소를 `data/incidents.db` SQLite WAL로 변경했다. 기존 JSON은
  최초 시작 시 무손실 이관하고 원본을 보존한다.
- `scripts/production_cutover.py`는 컷오프 이전 알림 DB 백업 후 legacy 아카이브,
  `scripts/install_soar_ufw_helper.sh`는 공개 IPv4 단건만 처리하는 제한 helper 설치.
- 2026-07-22 컷오버 완료: 기존 알림 110,748건은 `data/alerts_archive.db`로
  무손실 분리했고 활성 `alerts.db`는 24KB/0건에서 실데이터를 시작한다. 원본 DB
  복구본은 7MB gzip으로 보존한다. 인시던트 23,295건은 SQLite로 이관 완료했고
  두 JSON 세대는 각각 약 1.4MB gzip 복구본으로 보존한다.
- 실전 모드에서 AbuseIPDB 미설정/API 실패 시 데모 점수 fallback을 금지했다.
  컷오버 직후 잘못 생성된 MALWARE_BEACON 6건은 SYSTEM 오탐 확정·CLOSED 처리했다.
- 과거 simulate 차단 2,046건은 `blocklist_legacy_simulate_*.txt`로 무손실 분리해
  실전 UFW 활성 차단 통계와 혼동되지 않게 했다.
- Snort fast-alert 연동 및 보수적 자동 차단 증거 게이트 추가. Snort 단독 탐지는
  차단하지 않으며 기본값은 CRITICAL + 95% + 독립 근거 2개 + 분석가 승인이다.
- 안전 설치 스크립트 `scripts/setup_snort_ufw_safe.sh` 추가. sudo 비밀번호가
  필요해 Snort 패키지 설치와 UFW 규칙 변경은 아직 실행하지 않았다.
- Ubuntu Snort 2의 실제 fast 로그는 `/var/log/snort/snort.alert.fast`다. 설치기가
  전체 인터페이스를 선택한 경우 `scripts/repair_snort_single_interface.sh`로
  `eth0` 단일 센서와 `HOME_NET=172.23.160.0/20`으로 교정한다.
  Snort 2가 일반 종료 신호를 무시하면 시작 전에 남은 데몬을 강제 정리한다.
- UFW만 안전하게 활성화할 때는 `scripts/enable_ufw_safe.sh`를 사용한다. 기존
  iptables/UFW 상태 백업 후 SSH 22, HTTP 80, Tailscale 전체와 Tailscale 5055를
  먼저 허용하고 기본 inbound deny를 적용한다.
- AI 관제 센터에 Snort/UFW 보호 상태 카드를, 수집·탐지 사이드바에 전용 상세
  탭을 추가했다. API는 `GET /api/integrations/snort`, 화면 갱신은 보이는 탭에서
  10초 간격이며 최근 fast-alert SID/우선순위/통신 대상을 표시한다.
- 2026-07-21 측정 용량: 프로젝트 638MB(venv 493MB), 운영 데이터 111MB.
  alerts.db 60MB, SOAR DB+WAL 약 23MB, incidents.json+백업 약 22MB.
- 대시보드 렉 최적화: 브라우저별 AI 중복 분석 제거, 숨은 탭 렌더 중단,
  패킷 차트·SOAR 이벤트 스로틀, 알림 테이블 200행 배치 갱신, 대형 인시던트
  JSON 자동 병합 저장 5초 배치, SOAR SQLite WAL 적용
- AI 관제 센터를 중앙 흐름 제어 허브로 확장(승인 큐·상태·상세 탭 이동)
- 승인 큐 스냅샷 기반 최대 100건 일괄 승인(AI 관제 센터·SOAR 상세)
- IP 차단 수동 승인 게이트(승인·거절·취소·15분 만료 및 감사 추적)
- SOAR 실행 이력 SQLite 영구 저장 및 재시작 후 최근 100건 복원
- 실패한 VirusTotal 해시 조회의 안전한 재시도(`retry_of`, `attempt` 추적)
- SOAR 플레이북 실행 인스턴스와 단계별 실시간 상태 시각화
- VirusTotal v3 해시 평판 플레이북(`PB-MALWARE-ENRICH`, 파일 업로드 없음)
- SOAR EICAR 연결 테스트와 VirusTotal 결과의 알림·인시던트 영속 연계
- 계층별 데이터 보존 정책과 삭제 미리보기

2026-07-20 전체 테스트 실행 결과:

```bash
./venv/bin/python -m pytest -q
```

결과: `158 passed in 6.94s`

검토 시점에는 기존 작업 트리가 깨끗했다. 이 문서를 추가한 변경만 새로 생긴 상태다.

## 다음 작업 권장 순서

아래 항목은 검토만 했으며 아직 구현하지 않았다.

### 1. CORS, Socket.IO 출처 및 CSRF 보호

`app.py`에서 credential을 허용한 CORS와 Socket.IO가 모든 출처를 허용한다.

```python
CORS(app, supports_credentials=True)
cors_allowed_origins="*"
```

권장 작업:

- 허용 origin을 환경변수로 관리하고 기본값을 same-origin으로 제한
- 상태 변경 API에 CSRF 토큰 또는 엄격한 Origin 검증 적용
- `/logout`을 GET에서 POST로 변경
- 관련 인증·CORS·CSRF 통합 테스트 추가

### 2. 민감 API 권한 분리

현재 로그인 사용자 한 명이 조회부터 방화벽 차단, EDR 프로세스 종료, 패치, 원격 명령까지 모두 실행할 수 있다.

특히 점검할 API:

- `POST /api/soar/block`, `/api/soar/unblock`
- `POST /api/edr/kill`
- `POST /api/patch/run`, `/api/patch/command`
- 스캔·퍼징·퍼플팀 실행 API

권장 역할은 `viewer`, `analyst`, `responder/admin`이다. `/api/patch/command`는 위험 문자열 차단보다 승인된 명령 템플릿 또는 allowlist 방식이 안전하다.

### 3. 데이터 보존 정책 충돌 수정

현재 설정은 알림을 90일 후 아카이브하도록 설명하지만, `modules/retention.py`가 기본 3일이 지난 활성 알림과 아카이브 및 감사 로그를 영구 삭제한다.

관련 설정:

- `ALERT_RETENTION_DAYS=90`
- `ALERT_AUTO_ARCHIVE=False`
- `DATA_RETENTION_DAYS=3`

권장 정책:

- 활성 알림은 `ALERT_RETENTION_DAYS` 이후 아카이브
- 아카이브는 별도의 장기 보존 기간 적용
- 감사 로그는 최소 180~365일 또는 삭제 금지
- `DATA_RETENTION_DAYS`는 파일 로그와 임시 산출물에만 적용
- archive/retention 상호작용 테스트 추가

### 4. 앱 생성과 백그라운드 서비스 시작 분리

현재 `create_app()`이 모든 서비스를 시작하고, `app.py` import 시 아래 전역 코드가 즉시 실행된다.

```python
app, socketio = create_app()
```

이 때문에 테스트, Flask CLI, 다중 worker 환경에서 센서와 스레드가 중복 실행되거나 Syslog·허니팟 포트가 충돌할 수 있다.

권장 작업:

- `create_app(start_background=False)` 또는 별도 `start_runtime()` 도입
- 실제 실행 진입점에서만 수집 서비스 시작
- 모든 서비스의 `stop()` 계약과 종료 처리 통일
- 앱을 두 번 생성해도 센서가 중복 시작되지 않는 테스트 추가

### 5. 설정 및 API 입력 검증 통일

`config.py`에서 boolean 환경변수 일부가 문자열로 유지되고 각 모듈이 다시 문자열 비교를 한다. 공통 `env_bool()` 파서로 설정 로딩 시 타입을 확정하는 것이 좋다.

추가 권장 사항:

- `MAX_CONTENT_LENGTH` 설정 및 업로드 크기 제한
- API의 `limit`, `offset`, 문자열 길이와 배열 크기 상한 설정
- IP 입력을 `ipaddress.ip_address()`로 검증
- 채팅 및 AI context 크기 제한
- 환경변수 숫자 범위 검증
- 잘못된 입력을 500이 아닌 일관된 400 응답으로 처리

### 6. 운영 안정성과 관측 가능성

백그라운드 루프 곳곳에 `except Exception: pass`가 있어 장애 원인을 찾기 어렵다.

권장 작업:

- `print()`를 구조화된 `logging`으로 교체
- 예외 traceback, 마지막 성공 시각, 연속 실패 수, 재시작 수 기록
- readiness/liveness 엔드포인트 구분
- SQLite WAL, `busy_timeout`, 백업과 스키마 migration 적용
- 타임스탬프를 UTC로 저장하고 UI에서 로컬 시간으로 변환
- 운영 환경에서는 Werkzeug 대신 reverse proxy와 운영용 WSGI 구성 사용

## 테스트 보강 대상

현재 단위 테스트는 탐지 및 스캐너 로직을 잘 다루지만 다음 범위가 부족하다.

- 로그인, 세션 만료, 미인증 API와 Socket.IO 접근
- 역할별 권한
- CSRF 및 CORS
- 민감한 변경 API
- SQLite 실제 통합 테스트
- retention/archive 정책
- 앱 시작·종료와 다중 인스턴스
- 잘못된 API 입력
- 브라우저 기반 대시보드 smoke test

CI에는 최소한 `pytest`, Ruff, Bandit, dependency 취약점 검사와 secret scan을 권장한다.

## 실행 방법

```bash
cp .env.example .env
./venv/bin/python app.py
```

기본 설정은 데모 모드이며 실제 패치와 방화벽 작업은 simulate 상태다. 설정 변경 전 `.env.example`, `config.py`, `CLAUDE.md`의 안전 관련 설명을 함께 확인한다.

## 작업 시 주의사항

- 실제 센서가 없어도 실행 가능한 데모 fallback을 유지한다.
- Socket.IO emit과 공유 상태는 threading-safe하게 유지한다.
- 외부 연동은 `/api/integrations/{system}` 규칙을 따른다.
- 기존 런타임 데이터베이스와 `.env`는 사용자 데이터이므로 덮어쓰거나 삭제하지 않는다.
- 변경 후 전체 테스트를 실행하고 보안 관련 변경은 API 통합 테스트를 함께 추가한다.

## 다음 세션 시작점

가장 먼저 진행할 묶음은 다음과 같다.

1. CORS/Socket.IO origin 제한
2. CSRF 또는 Origin 검증 도입
3. 민감 API 역할 검사
4. 3일 영구 삭제 정책과 90일 아카이브 정책 충돌 해소

기능 추가를 먼저 해야 한다면 위 항목을 즉시 구현하지 않더라도, 외부 공개 또는 실제 `apply`/`kill`/방화벽 모드를 활성화하기 전에는 반드시 재검토한다.
