# SOC Dashboard 코드 감사 보고서

**감사일**: 2026-08-27 · **기준 커밋**: `8c7e78a` · **브랜치**: `main`
**범위**: `modules/` 40개 · `api/` 88개 엔드포인트 · `static/js/dash/` 18파일 · `templates/panels/` 33개 · `tests/` 184개
**규모**: 앱 코드 13,183 LOC (테스트 2,211 별도) · JS 5,251 LOC · 템플릿 3,113 LOC

이 문서의 모든 항목은 코드 실행 또는 파일:라인 확인으로 검증했다. 추정한 부분은 명시했다.

---

## 잘된 부분 (1문단)

방화벽 차단 경로의 다중 방어가 실제로 작동한다. `SOAREngine._is_blockable`(`modules/soar.py:962`)이 `ipaddress` 파싱 → 공인 IPv4 검사 → 사설/CGNAT/자기자신/화이트리스트를 순차 거부하고, 그 아래 `scripts/soc-ufw`가 셸 레벨에서 정규식·옥텟·보호대역을 **독립적으로 재검증**한다(`scripts/soc-ufw:16-30`). 앱이 뚫려도 helper가 사설망 차단을 거부한다. 이 안전장치에는 경계값 회귀 테스트도 있다(`tests/test_detection.py:473-511`). 전체 코드베이스에 `shell=True`·`os.system`이 0건이고 모든 `subprocess`가 리스트 인자다. 모듈 데모 fallback 규칙도 예외 없이 지켜져 센서 없는 환경에서 184개 테스트가 통과한다.

---

## 심각도 정렬 표

| # | 심각도 | 제목 | 근거 | 작업량 |
|---|--------|------|------|--------|
| 1 | ~~P0~~ **수정됨** | CORS가 임의 Origin을 credentials와 함께 반영 | `app.py:62` | ✅ |
| 2 | ~~P0~~ **수정됨** | 상태변경 POST 40여 개에 CSRF 방어 없음 | `app.py:62`, `api/*` | ✅ |
| 3 | ~~P1~~ **수정됨** | 파괴적 명령 blocklist 우회 가능 (`rm -fr /` 통과) | `modules/patch_manager.py:28-32,405` | ✅ |
| 4 | ~~P1~~ **수정됨** | 인시던트 저장이 매번 전량 재작성 — 0.63s 동안 락 점유 | `modules/incidents.py:311-347` | ✅ |
| 5 | ~~P1~~ **수정됨** | `id NOT IN (?×23299)` — 32,766건에서 무성 실패 | `modules/incidents.py:323` | ✅ |
| 6 | ~~P1~~ **부분 수정** | incidents.db(18MB)·soar_executions.db(48MB) 보존정책 없음 | `modules/retention.py:12` | ⚠️ |
| 7 | **P1** | Anthropic 클라이언트 타임아웃 미설정 + 동기 chat | `modules/ai_analyst.py:52,92`, `app.py:153` | S |
| 8 | ~~P1~~ **수정됨** | 허니팟/Syslog 연결당 무제한 스레드 생성 | `modules/honeypot.py:164` | ✅ |
| 9 | **P1** | 라우트 88개에 예외 처리·에러 핸들러 전무 | `api/*.py` (try 0건) | M |
| 10 | **P1** | `api/`·`app.py`·`wiring.py` 테스트 커버리지 0% | 측정치 | L |
| 11 | **P2** | 보안 헤더(CSP·X-Frame-Options 등) 전무 | 실측 확인 | S |
| 12 | **P2** | 문서화된 탐지 임계값 env가 죽어 있음 (하드코딩) | `modules/threat_detector.py:236,251` | S |
| 13 | **P2** | 아카이브 알림 110,748건이 모든 조회 경로에서 불가시 | `modules/alert_store.py:171` | M |
| 14 | **P2** | `.env.example`에 25개 변수 누락 · `SIEM_CORR_*`는 config에도 없음 | 비교 결과 | S |
| 15 | **P2** | 프론트 XSS 이스케이프 불일치 (확증된 경로 없음) | `02-overview.js:257` 외 | S |
| 16 | **P2** | CDN 9개 의존 · SRI 없음 · 오프라인 불가 | `templates/dashboard.html:252-261` | S |
| 17 | **P2** | `print()` 102회 · 구조화 로깅 없음 | 전역 | M |
| 18 | **P2** | 린터·CI·Dockerfile 전부 부재 | 파일 없음 | M |
| 19 | **P2** | `test_patch_check_runs` 환경 의존 flaky | `tests/test_detection.py:1017` | S |
| 20 | **P2** | README 수치가 실제와 불일치 (모듈/LOC/테스트 수) | `README.md:14,164,206` | S |
| 21 | **P2** | alert_store·audit_log·watchlist에 WAL/busy_timeout 미설정 | `alert_store.py:16` 외 | S |
| 22 | **P3** | `get_services()` 6-튜플 위치 결합 | `api/_common.py:36` | S |
| 23 | **P3** | JS 전역 선언 323개 · 로드 순서 의존 | `static/js/dash/*` | L |
| 24 | **P3** | `_attackerCounter` 무한 증가 + 알림마다 전량 정렬 | `02-overview.js:101-105` | S |
| 25 | **P3** | 미사용 import 40건 · 타입힌트 1% | pyflakes | S |
| 26 | **P3** | 저장소명 오타 `DaschBoard` | git remote | S |
| 27 | **P3** | `SESSION_COOKIE_SECURE` 기본 False · `allow_unsafe_werkzeug=True` | `config.py:144`, `app.py:188` | S |

---

## 상위 10개 우선순위 요약

1. ~~**CORS + CSRF (P0 #1, #2)**~~ — ✅ 수정 완료 (`fix/p0-cors-csrf`)
2. ~~**파괴적 명령 blocklist 우회 (P1 #3)**~~ — ✅ 수정 완료 (`fix/p0-cors-csrf`)
3. **인시던트 저장 전량 재작성 (P1 #4)** ← 현재 최우선 — 탐지 파이프라인을 주기적으로 정지시킨다.
4. **인시던트 32,766건 상한 (P1 #5)** — 남은 여유 9,467건, 실패가 조용하다.
5. **DB 보존정책 공백 (P1 #6)** — 66MB가 정책 밖에서 무한 증가 중.
6. **AI 호출 타임아웃 (P1 #7)** — 최대 30분 스레드 점유.
7. **연결당 무제한 스레드 (P1 #8)** — 허니팟을 문서 권장대로 외부 노출하는 순간 자기 자신이 DoS 대상.
8. **라우트 예외 처리 부재 (P1 #9)** — 모듈 예외가 곧 500 HTML.
9. **api/ 커버리지 0% (P1 #10)** — 위 수정들을 검증할 안전망이 없다. 사실상 #1~#9의 선행 조건.
10. **보안 헤더 + 탐지 임계값 사문화 (P2 #11, #12)** — 보안 도구로서의 신뢰도에 직접 영향.

---

## A. 구조 / 유지보수성

### A-1. `wiring.py`는 God object가 아니다 (반대 의견)

의뢰에서 지목한 항목이지만, 확인 결과 **문제 없다**. `wiring.py:36-190`의 `build_services()`는 상태를 갖지 않고 로직도 없다. 인스턴스를 만들고 의존성을 주입한 뒤 `app.*`에 등록하고 끝난다 — 전형적인 **composition root** 패턴이고, 이것이 정석이다. 의존 방향이 한 파일에 모여 있어서 `threat_detector.soar = soar`(`wiring.py:71`) 같은 배선을 grep 없이 읽을 수 있는 것은 오히려 이 프로젝트의 강점이다.

순환참조도 없다. `modules/` 내부에 모듈 간 `import`가 0건이고, 결합은 전부 생성자 주입 또는 사후 속성 대입으로 이루어진다. `python -c "import wiring"`이 순환 없이 성공한다.

**다만 실제 결합 문제는 따로 있다**: `threat_detector`가 `threat_intel`·`ip_reputation`·`soar`·`decision`·`watchlist`·`siem_correlator`까지 6개를 사후 대입으로 받는다(`wiring.py:59,63,70,84,111,146`). 이건 `ThreatDetector`가 파이프라인 오케스트레이터 역할까지 겸하고 있다는 뜻이고, 652 LOC라는 크기가 그 증상이다. 쪼갠다면 여기다 — 다만 지금 우선순위는 아니다.

### A-2. 책임 중복 / 크기

| 모듈 | LOC | 판정 |
|------|-----|------|
| `soar.py` | 1,014 | **분리 후보**. 플레이북 정의·실행 이력·차단 실행·승인 워크플로 4개 책임. 다만 실행 이력은 이미 `soar_execution_store.py`로 분리됨 — 나머지는 현 상태 유지 가능 |
| `vuln_scanner.py` | 701 | 유지. 스캔 엔진 단일 책임 |
| `threat_detector.py` | 652 | 위 A-1 참조 |
| `correlation.py`(71) / `siem_correlation.py`(249) | — | **이름이 혼동을 부른다.** 전자는 알림 이력 기반 캠페인 재구성(배치), 후자는 실시간 스트림 상관(윈도우). 합칠 필요는 없지만 `campaign_builder.py` / `stream_correlation.py`로 개명하면 읽기 쉬워진다 |

40개 모듈 중 합쳐야 할 만큼 중복된 쌍은 없다. 각 모듈이 `start()`/`stop()`/`get_*()` 인터페이스를 지키고 있어 개수 자체는 문제가 아니다.

### A-3. API 계층 일관성 — [P1] 예외 처리 전무

**근거**: `api/*.py`에서 `try:` 0건, `@errorhandler` 0건 (grep 확인).

- **에러 처리**: 라우트 88개 중 예외를 잡는 곳이 하나도 없다. `app.vuln_scanner`가 예외를 던지면 클라이언트는 JSON을 기대한 자리에서 Flask 500 HTML을 받는다. 프론트의 `.then(r => r.json())`이 파싱 에러로 죽고, `.catch(() => {})`(예: `15-syslog.js:8`)가 이를 삼켜 **패널이 조용히 빈 채로 남는다**.
- **응답 스키마**: 성공 응답이 제각각이다. `{"alerts": [...], "total": n}`(detection_routes.py:91), 최상위 배열, 벌거벗은 객체(`jsonify(vs.get_status())`)가 섞여 있다. 에러는 `{"error": "..."}`로 비교적 일관적이나 HTTP 코드 부여가 들쭉날쭉하다.
- **페이지네이션**: 7개 엔드포인트만 `page`/`limit`을 지원하고 나머지는 `limit` 하드코딩 또는 전량 반환이다. `/api/incidents`는 `limit=100` 고정으로 23,299건 중 100건만 보여준다.

**✅ 수정 완료** (`fix/api-error-handling`, 2026-08-27):

서버 측 — `app.py` 에 핸들러 2개:
- `@app.errorhandler(HTTPException)` — 404/405/403 등을 `/api/` 경로에서는 JSON 으로. 그 외 경로는 기존 HTML 을 유지한다(대시보드 페이지까지 JSON 으로 바꾸면 브라우저 UX 가 깨진다).
- `@app.errorhandler(Exception)` — 서버 로그에는 전체 트레이스백, 클라이언트에는 **8자리 `error_id`**. 예외 메시지에 내부 경로·구조가 섞일 수 있어 그대로 내보내지 않고, `DEBUG=True` 일 때만 `detail` 을 붙인다.

프론트 측 — 호출부 39곳을 고치는 대신 **`fetch` 를 한 겹 감쌌다**(`01-core.js`). 응답 본문은 `clone()` 에서만 읽으므로 기존 코드는 그대로 동작하고, `/api/` 응답이 실패했을 때만 우하단에 배너가 뜬다. 같은 오류가 반복되면 쌓지 않고 `×N` 으로 센다. `auth_required` 는 배너 대신 로그인 페이지로 보낸다.

부수 정리: `escapeHtml` 이 `04-ml-mitre.js` 에 정의돼 있는데 `01-core.js` 부터 쓰이고 있었다. 런타임에는 동작하지만 로드 순서에 취약해 `01-core.js` 로 옮겼다.

테스트 13건 (`tests/test_api_error_handling.py`) — 404/405 JSON 화, 모듈 예외 시 JSON 500, `error_id` 유일성, 비DEBUG 시 내부 정보 미노출, 의도적 4xx·CSRF 403 이 삼켜지지 않는지, **인자 없는 GET 엔드포인트 전수**가 JSON 을 돌려주는지(파일 다운로드 1개 제외), CSV 내보내기 실패 시에도 JSON 인지.

### A-4. 죽은 코드 / 미사용 import — [P3]

pyflakes 40건. 대표적인 것:

- `api/*.py` 5개 파일이 `_hash_scan_allowed`를 import하지만 실제 사용은 `detection_routes.py:251` 한 곳뿐. `get_services`·`_mitre`도 3개 파일에서 미사용.
- `modules/ml_analyst.py:27` `tensorflow as tf` — requirements에서 주석 처리된 선택 의존성인데 import 후 미사용.
- f-string 자리표시자 누락 8건 (`app.py:54,57,146,150,179`, `soar.py:152`, `daily_report.py:244-258`) — 동작에는 영향 없으나 린터가 잡을 노이즈.

**✅ 수정 완료** (`ci/github-actions`): 미사용 import 와 불필요한 f-string 접두사 20건을 정리했다(`ruff --fix` 19건 + 수동 1건). 이제 `ruff check .` 가 깨끗하며 CI 가 매 push 마다 검사한다.

의도적인 것은 남겼다:
- `api/routes.py` — 임포트 부수효과로 라우트를 등록한다. 지우면 엔드포인트 94개가 사라진다. `pyproject.toml` 의 `per-file-ignores` 로 명시했다.
- `sysmon_parser` 의 `win32evtlogutil`/`win32con` — pywin32 일괄 가용성 확인용. `# noqa: F401` 과 사유 주석을 달았다.

부수 발견: `sysmon_parser._detect_metasploit` 의 지역변수 `path` 가 미사용이었는데, 규칙 6의 주석은 "의심 **경로**에서 실행되는 인코딩된 PowerShell"이라고 되어 있었다. **경로 검사가 구현된 적이 없다.** 없는 탐지를 새로 만들지 않고 변수를 제거하며 주석을 실제 동작에 맞췄다. `image_path` 기반 판정(Temp/AppData 실행 등)은 미구현 항목으로 남는다.

복붙 중복 로직은 **프론트에 집중**되어 있다. 각 패널 JS가 동일한 "fetch → 실패 시 무시 → tbody.innerHTML 교체" 패턴을 18번 반복한다(`13-watchlist.js:75`, `18-snort.js:77`, `16-honeypot.js:99` 등이 구조적으로 동일). 백엔드 쪽 중복은 심각하지 않다.

### A-5. 타입 힌트 / 린터 — [P3]

`def` 649개 중 반환 애노테이션 8개(**1.2%**), 인자 애노테이션 12개. `ruff`/`mypy`/`flake8`/`pyproject.toml`/`setup.cfg` 전부 부재.

**✅ 부분 수정** (`ci/github-actions`, 2026-08-27): `ruff` 를 도입하고 `pyproject.toml` 에 설정했다.

규칙은 **`F`(pyflakes)만** 켰다. `E,W,I` 를 한 번에 켜면 기존 코드 전반에 수백 건이 뜨고, 일괄 수정하면 리뷰 불가능한 대형 diff 가 된다. 점진적으로 넓힌다.

mypy 는 도입하지 않았다 — 타입 힌트 커버리지가 1.2% 라 지금 켜면 소음만 낸다. 새 코드에만 힌트를 붙여 나가다 커버리지가 오르면 재검토한다. 이 판단을 `pyproject.toml` 주석에 남겼다.

### A-6. `get_services()` 6-튜플 — [P3]

`api/_common.py:36`이 6-튜플을 반환하고 호출부가 `_, td, *_ = get_services()`(`detection_routes.py:75`) 또는 `_, _, _, hc, _, _ = get_services()`(`detection_routes.py:246`)로 언패킹한다. 순서를 바꾸면 조용히 잘못된 서비스가 바인딩된다. `current_app.threat_detector`를 직접 쓰는 편이 안전하고 짧다. **작업량 S**

---

## B. 운영 신뢰성

### B-1. [P1] 인시던트 저장이 매번 전량을 재직렬화하고, 그 동안 락을 잡는다

**근거**: `modules/incidents.py:311-331`(`_save_sqlite`), `:333-347`(`_schedule_save`)

`_save_sqlite()`는 변경분이 아니라 **`self.incidents` 전체**를 `json.dumps` 후 `executemany` upsert 한다. 실제 DB로 측정한 결과:

```
_load (23,299건 메모리 적재)      : 0.41s
_save_sqlite 1회 (전량 재직렬화)  : 0.63s
메모리 상 인시던트                : 약 30 MB
```

`flush()`가 `self._lock`을 잡은 채 이 0.63초를 소비한다(`incidents.py:342-344`). 같은 락을 `promote_alert()`(`:58`)와 `attach_block()`(`:107`)이 쓴다 — **즉 SOAR 정탐 승격 경로가 5초마다 0.63초씩 멈춘다.** 알림이 몰리면 디바운스가 연속 발화하므로 코어 하나의 ~13%를 변경 없는 데이터 재작성에 쓰면서 탐지 경로를 지속적으로 블로킹한다. `data/incidents.db-wal`이 4.4MB까지 부푼 것이 그 흔적이다.

**✅ 수정 완료** (`perf/incident-save`, 2026-08-27): 변경된 인시던트 id 만 `_dirty` set 으로 추적해 그것만 upsert 한다.

DB I/O 를 락 밖으로 빼는 방안은 **채택하지 않았다.** `update()` 가 락을 잡은 채 `_save()` 를 호출하고 `threading.Lock` 은 재진입 불가라, 구조를 바꾸면 데드락 위험이 생긴다. dirty set 만으로 락 점유가 O(23,299) → O(변경분)이 되어 문제가 해소되므로 더 안전한 쪽을 택했다.

실측 (실제 23,299건 DB):

| | 이전 | 이후 |
|---|---|---|
| 변경 없는 저장 | 630ms | **0.005ms** |
| 1건 변경 저장 | 630ms | **4.55ms** |
| 100건 승격+저장 | ~63s | **0.27s** |

`_load_sqlite` 직후에는 `_dirty` 를 비운다 — 방금 DB 에서 읽은 것을 다시 쓸 이유가 없다. 저장 실패 시 `_dirty` 를 유지해 다음 저장에서 재시도한다(비우면 그 변경분이 영영 유실된다).

### B-2. [P1] `id NOT IN (?×23,299)` — 32,766건에서 조용히 실패한다

**근거**: `modules/incidents.py:320-323`

```python
ids = [r[0] for r in rows]
marks = ",".join("?" for _ in ids)
self._db.execute(f"DELETE FROM incidents WHERE id NOT IN ({marks})", ids)
```

SQLite 3.32+ 기본 `SQLITE_MAX_VARIABLE_NUMBER`는 32,766이다(현재 환경 3.37.2 확인). 현재 23,299건 → **여유 9,467건**. 초과 시 `sqlite3.OperationalError: too many SQL variables`가 발생하는데, `:330`의 `except (OSError, sqlite3.Error, ...)`가 이를 잡아 `print`만 하고 넘어간다. **인시던트 영속화가 완전히 멈춘 채 대시보드는 정상으로 보인다.**

현재 인시던트 증가는 거의 정지 상태다(최근 7일 갱신 0건 — 서버가 내려가 있음). 임박한 위험은 아니지만, 상한이 존재하고 실패가 무성이라는 조합이 P1인 이유다.

**✅ 수정 완료** (`perf/incident-save`, 2026-08-27): 재조정 쿼리를 **제거**했다.

이 쿼리는 "메모리에 없는데 DB 에만 있는 행"을 지우려는 것인데, `self.incidents` 에 `del`/`pop`/`clear` 가 **0건**이다. 인시던트는 프로세스 내에서 삭제되지 않으므로 그런 행이 생길 수 없다. 삭제 기능이 생기면 그때 삭제 목록을 따로 추적한다.

검증: 33,000건(상한 32,766 초과)을 만들어 저장이 끝까지 성공하고, 그 규모에서 1건 갱신도 정상임을 확인하는 회귀 테스트를 추가했다 (`test_no_variable_limit_on_large_incident_count`).

### B-3. [P1] `incidents.db`·`soar_executions.db`에 보존정책이 없다

**근거**: `modules/retention.py:12`의 `_FILE_TARGETS`와 `run_cleanup()`(`:51-79`)이 다루는 대상은 alerts(라이브→아카이브), alerts_archive, audit, 파일 산출물뿐이다. `soar_execution_store.py`에 `purge`/`delete` 메서드가 0건, `incidents.py`도 마찬가지.

현재 크기:

| DB | 크기 | 행 수 | 보존정책 |
|----|------|-------|----------|
| `alerts.db` | 96 KB | 99 | ✅ 90일 |
| `alerts_archive.db` | 78 MB | 110,748 | ✅ 365일 |
| `audit.db` | 16 KB | 15 | ✅ 365일 |
| `soar_executions.db` | **48 MB** | 38,558 | ❌ **없음** |
| `incidents.db` | **18 MB** | 23,299 | ❌ **없음** |

메모리 상 `deque(maxlen=100)`로 제한되어 있는 건 UI 표시분일 뿐(`soar.py:91`), 디스크는 무한히 쌓인다.

**⚠️ 부분 수정** (`feat/db-retention`, 2026-08-27): 정책은 넣었으나 **현재 회수량은 0이다.** 그 이유가 더 중요한 발견이다.

구현한 것:
- `IncidentManager.purge_resolved_older_than(days)` — **RESOLVED 만** 대상. OPEN/INVESTIGATING/CONTAINED 는 분석가의 진행 중 작업이라 절대 지우지 않는다. 메모리와 DB 양쪽에서 제거.
- `SOARExecutionStore.purge_terminal_older_than(days)` — 종료된 실행만. `waiting_approval`·`processing_approval`·`running`·`pending` 은 **제외 목록**으로 정의했다. 새 상태값이 생겨도 기본이 '보존'이 되게 하기 위함이며, 특히 `waiting_approval`(실 DB 1,685건)은 사람의 결정을 기다리는 항목이라 지우면 그 결정 기회가 사라진다.
- config: `INCIDENT_RETENTION_DAYS`(365) · `SOAR_EXECUTION_RETENTION_DAYS`(90).

실 데이터에 적용 시 회수량 (조회만 수행):

| 대상 | 전체 | 정리 대상 | 사유 |
|---|---|---|---|
| 인시던트 | 23,299 | **0** | RESOLVED 가 **0건** — 어떤 기간을 잡아도 0 |
| SOAR 실행 | 38,573 | **0** (90일 기준) | 데이터가 37일치뿐. 30일 기준으로는 36,873건 |

**SOAR 쪽은 정상이다** — 시간이 지나면 정책이 작동한다(30일 기준 36,873건이 대상). 무한 증가가 실제로 막혔다.

**인시던트 쪽은 구조적으로 작동하지 않는다.** → 아래 B-3a 참조.

### B-3a. [~~P1~~ **수정됨**·신규] 인시던트가 종료되는 경로가 없다

B-3 수정 중 발견했다. 실 DB 23,299건의 상태 분포:

```
OPEN           20,898
INVESTIGATING   2,401
CONTAINED           0
RESOLVED            0
```

**RESOLVED 가 0건이고, CONTAINED 도 0건이다.** 코드를 확인한 결과:

- `RESOLVED` 를 설정하는 경로는 `IncidentManager.update()` — 즉 **분석가의 수동 조작뿐**이다. 자동 종료 경로가 없다.
- 감사 로그(`audit.db`)에 인시던트 관련 조치 기록이 **0건**이다. 수동으로도 종료된 적이 없다.
- `attach_block()` 이 OPEN → INVESTIGATING 으로 올리는 것이 유일한 자동 전이다.

결과적으로 **인시던트는 생성되기만 하고 절대 닫히지 않는다.** `incidents.db` 18MB 의 진짜 원인은 보존정책 부재가 아니라 이것이다. 보존정책은 RESOLVED 를 대상으로 하므로 영원히 아무것도 지우지 않는다.

부수 영향: `soc_metrics` 의 MTTR 은 "생성 → RESOLVED/CONTAINED 까지의 시간"인데(`soc_metrics.py:54`) 둘 다 0건이므로 **MTTR 지표가 산출되지 않거나 무의미하다.**

**✅ 수정 완료** (`feat/incident-auto-resolve`, 2026-08-27): 1번(자동 종료)을 채택했다.

`IncidentManager.auto_resolve_stale(days)` — 마지막 활동 후 N일간 새 활동이 없는 인시던트를 RESOLVED 로 전이한다. `INCIDENT_AUTO_RESOLVE_DAYS`(기본 30, 0이면 비활성)로 조정한다.

**조용한 종료가 아니다.** 각 인시던트 타임라인에 사유와 **이전 상태**를 남긴다:

```
자동 종료 — 30일간 신규 활동 없음 (이전 상태: OPEN)
```

새 알림이 오면 `_find_active` 가 RESOLVED 를 제외하므로 **새 인시던트로 다시 열린다**(`test_new_alert_after_auto_resolve_opens_new_incident`).

retention 루프에서 **자동 종료 → 정리** 순서로 돈다. 방금 종료된 건은 `updated` 가 갱신되므로 같은 회차에 삭제되지 않고 보존기간(365일)이 새로 시작된다.

실 DB 사본 검증:

```
자동 종료 대상 : 23,299 / 23,299건  (전량이 30일 이상 조용)
종료 처리      : 23,299건, 0.87초   (6시간마다 1회, 첫 실행만)
2회차 대상     : 0건
즉시 삭제 대상 : 0건                (보존기간 새로 시작 — 의도대로)
재기동 후      : RESOLVED 23,299건 전량 보존
```

부수 효과: MTTR 지표가 산출 가능해진다. 다만 첫 회차의 MTTR 은 "생성 → 자동 종료"이므로 실제 대응 속도가 아니라 **자동 종료 기간(30일)을 반영한다** — 지표 해석 시 주의가 필요하다.

2·3번은 채택하지 않았다. 2번(승격 조건 강화)은 dedup 레이어가 알림을 31.2% 줄이므로 승격량이 자연히 감소한다. 3번(일괄 종료 UI)은 자동 종료가 있으면 상시 필요하지 않다.

### B-4. [P1] 외부 호출 회복력 — Anthropic만 무방비

| 대상 | 타임아웃 | 재시도 | 서킷브레이커 |
|------|----------|--------|--------------|
| Anthropic | ❌ **미설정** | SDK 기본 2회 | ❌ |
| AbuseIPDB | ✅ 6s (`ip_reputation.py:206`) | ❌ | ✅ 캐시 6h |
| VirusTotal | ✅ 설정값 (`virustotal.py:41`) | ❌ | ✅ 캐시 6h |
| ip-api.com | ✅ 3s (`geoip.py:48`) | ❌ | ✅ 레이트리밋 |
| nmap | ✅ 180s (`vuln_scanner.py:564`) | ❌ | — |
| ansible | ✅ 300~600s (`patch_manager.py:324,424`) | ❌ | — |

`anthropic.Anthropic(api_key=...)`(`ai_analyst.py:52`)에 `timeout`·`max_retries`를 주지 않았다. SDK 기본은 **10분 타임아웃 × 최대 3회 시도**다. 워커 루프(`:115`)는 예외를 잡으므로 스레드는 살아남지만, 큐가 최대 30분 정체된다.

더 나쁜 쪽은 챗봇이다. `on_chat`(`app.py:153`)이 `app.ai_analyst.chat()`을 **동기로** 호출하고, `chat()`은 `_do_chat` → `messages.create`를 그대로 탄다(`ai_analyst.py:92`). threading 모드 SocketIO에서 이는 요청 처리 스레드를 최대 30분 잡는다는 뜻이다.

**✅ 수정 완료** (`fix/ai-resilience`, 2026-08-27):

- `anthropic.Anthropic(api_key=..., timeout=30.0, max_retries=1)` — 최악 대기가 30분 → **60초**로 제한된다. `AI_TIMEOUT_SECONDS`/`AI_MAX_RETRIES` 로 조정.
- **서킷브레이커 신설** — 연속 실패가 `AI_BREAKER_THRESHOLD`(기본 3)를 넘으면 `AI_BREAKER_COOLDOWN`(기본 300초) 동안 호출을 멈추고 규칙 기반 판정으로 대체한다. API 가 죽었을 때 알림마다 타임아웃을 기다리는 것을 막는다. 결과에 `degraded: true` 와 사유를 실어 UI 가 열화 상태임을 알 수 있다.
- **타입별 예외 처리** — 하나의 광범위한 `except Exception` 으로는 재시도 가능한 실패(429/5xx/네트워크)와 불가능한 실패(401/400/모델 없음)를 구분할 수 없다. `APITimeoutError` → `RateLimitError` → `AuthenticationError` → … 순으로 좁은 것부터 잡아 사람이 읽을 사유로 바꾼다.
- `/api/ai/status` 의 `resilience` 필드로 브레이커 상태·연속 실패 수·마지막 오류·호출 통계를 노출한다.

**챗봇 비동기화는 하지 않았다.** 확인 결과 프론트엔드가 챗봇을 **전혀 사용하지 않는다**(`chat_message` emit 0건, `/api/ai/chat` fetch 0건). 동기 호출이 남아 있지만 클라이언트 타임아웃으로 최대 60초로 제한되므로, 쓰이지 않는 경로를 위해 SocketIO 세션 처리를 재구성하는 것은 균형이 맞지 않는다고 판단했다. 사용하게 되면 그때 비동기로 전환한다.

테스트 17건 (`tests/test_ai_resilience.py`) — 브레이커 개폐, 차단 중 API 미호출, 쿨다운 후 복구, 성공 시 카운터 초기화, AI 실패 시에도 파이프라인이 결과를 받는지.

### B-5. [P1] 연결당 무제한 스레드 생성

**근거**: `modules/honeypot.py:164`, `modules/syslog_receiver.py:223`

```python
threading.Thread(target=self._handle_conn, args=(conn, addr[0], port, service),
                 daemon=True).start()
```

동시 연결 수 제한이 없다. 세마포어도, 스레드풀도 없다. 허니팟은 소켓 타임아웃 3초(`:171`)로 수명이 짧지만, `CLAUDE.md`와 `config.py:56`이 **"실포착은 `HONEYPOT_BIND=0.0.0.0` + 외부 노출"**을 권장한다. 그 구성에서 초당 수천 연결을 던지면 SOC 대시보드 자신이 스레드 고갈로 죽는다. Syslog TCP는 타임아웃 30초(`:227`)에 `listen(16)`이지만 accept 후 스레드는 무제한이므로 더 적은 연결로 같은 결과가 난다.

**✅ 수정 완료** (`fix/conn-limits`, 2026-08-27): `BoundedSemaphore` 로 동시 핸들러 상한을 뒀다.

- 허니팟 `HONEYPOT_MAX_CONNS`(기본 200), Syslog TCP `SYSLOG_MAX_CONNS`(기본 50).
- 상한 초과 시 즉시 `close()` 하고 `rejected` 카운터를 올린다.
- **허니팟은 거부된 접촉도 이벤트로 기록한다.** 배너 교환·입력 수집은 포기하더라도 "이 IP 가 접촉했다"는 탐지 가치는 지켜야 하기 때문이다(`rejected: true` 표시). 조용히 버리지 않는다.
- Syslog 는 거부해도 전송단이 재시도하고 UDP 경로가 함께 열려 있어 로그를 영구히 잃지 않는다.
- `active_conns`/`rejected`/`max_conns` 를 상태에 노출한다. `rejected` 가 0이 아니면 공격 규모가 상한을 넘었다는 신호다.

실측 (허니팟 상한 50, 연결 500회 시도):

```
기준 스레드 수 : 2
시도 후        : 52  (증가 50 = 상한과 정확히 일치)
활성 연결      : 50
거부           : 3
```

정직하게 덧붙이면, 500회 중 실제로 연결된 것은 53개다 — OS listen 백로그(`honeypot.py:157` `listen(8)`)가 차서 나머지는 connect 단계에서 실패했다. **즉 백로그가 1차 완충 역할을 하고 있었고, 세마포어는 그것을 넘어선 지속적 연결에 대한 보장이다.** 폭주 재현에는 지속적 연결 부하가 필요하다.

테스트 16건 (`tests/test_conn_limits.py`) — 세마포어 단위 테스트가 아니라 **실제 소켓으로 연결을 밀어넣어** accept 루프와의 결합까지 검증한다. 슬롯 반환, 정상 유인 동작 유지, 설정값 방어 포함.

**이제 `HONEYPOT_BIND=0.0.0.0` 외부 노출의 전제 조건이 해소됐다** — `docs/CASE_STUDIES.md` 의 "사례를 더 모으려면" 4번 항목.

### B-6. 백그라운드 스레드 생명주기 — 대체로 양호, 종료 훅만 부재

- 스레드 생성 지점 40곳 **전부 `daemon=True`** (Timer 포함, `incidents.py:347`에서 명시적 설정). 종료 시 행(hang) 위험 없음.
- 각 모듈에 `stop()`이 있으나 **호출하는 곳이 어디에도 없다** (`app.py`·`wiring.py`·`api/` grep 0건). Ctrl-C 시 인시던트 디바운스 타이머가 대기 중이면 최대 5초분의 인시던트 갱신이 유실된다. 실질 영향은 낮다.
- **예외로 인한 스레드 사망 후 무성 침묵**: 주요 루프는 모두 `while` 내부에 `try/except Exception`을 두고 있어 사망하지 않는다(`ai_analyst.py:115-131`, `retention.py:86-92`, `wiring.py:222-229`). `wiring.py`의 ML 피드 루프만 `except Exception: pass`로 완전 무음이라 ML 패널이 조용히 멈춰도 알 길이 없다 — 로깅 한 줄 추가로 해결.

### B-7. SQLite 동시성 — "database is locked"는 나지 않으나 설계가 불균질하다

5개 저장소 전부 `check_same_thread=False` + 단일 커넥션 + 전역 `threading.Lock` 구조다. 프로세스 내 접근은 락으로 직렬화되므로 **threading 모드 SocketIO에서 `database is locked`는 발생하지 않는다** — 이 부분은 의뢰의 우려와 달리 문제없다.

다만 설정이 불균질하다:

| 저장소 | WAL | synchronous | busy_timeout |
|--------|-----|-------------|--------------|
| `incidents.py:282` | ✅ | NORMAL | ❌ |
| `soar_execution_store.py:17` | ✅ | NORMAL | ❌ |
| `alert_store.py:16` | ❌ | 기본 | ❌ |
| `audit_log.py:34` | ❌ | 기본 | ❌ |
| `watchlist.py:25` | ❌ | 기본 | ❌ |

WAL이 없는 3개는 **외부 프로세스**(`scripts/production_cutover.py`, 백업 스크립트, sqlite3 CLI)가 동시에 붙는 순간 잠금 충돌이 난다. 실제로 이 감사 중 sqlite3로 읽을 때 문제는 없었지만, 쓰기가 겹치면 다르다.

또 하나: `alert_store`의 전역 락은 `aggregate(days=14)`(`:231-283`) 같은 6개 집계 쿼리 묶음이 도는 동안 `save()`를 전부 막는다. 현재 `alerts` 테이블이 99행이라 무해하지만, 라이브 알림이 90일치 쌓이면 `/api/metrics/soc` 호출 한 번이 탐지 경로를 막는다. **읽기 전용 별도 커넥션**을 쓰면 해결된다. **작업량 S**

### B-8. 실패 전파 — 격리는 잘 되어 있다

한 모듈이 죽어서 대시보드 전체가 죽는 경로는 **찾지 못했다**. `system_health.py`가 방어적 `getattr` 조회를 하고, `_emit()` 계열이 전부 `except Exception: pass`로 감싸여 있으며(`incidents.py:202-210`), 모듈 간 직접 import가 없다. 다만 그 대가가 B-9의 문제다.

### B-9. [P2] 로깅 — `print()` 102회, 구조화 로깅 없음

`modules/`·`api/`·`app.py`·`wiring.py`에 `print()` 102회. `logging`을 쓰는 파일은 `app.py` 하나뿐이고, 그마저 werkzeug 로그를 **끄는** 용도다(`app.py:12-15`). `logs/server.out`으로 리다이렉트한 stdout이 사실상 유일한 로그다.

여기에 `except Exception: pass` 81건이 겹친다. 레벨도, 타임스탬프도, 모듈명도, 검색 가능한 필드도 없다. **보안관제 도구가 자기 자신의 관측성을 갖고 있지 않다.**

**수정 방향**: `logging.getLogger(__name__)` + 모듈명 prefix 포맷터. 구조화(JSON) 로깅은 그 다음 단계. `print(f"[SOAR] ...")` 패턴이 일관적이라 기계적 치환이 가능하다. **작업량 M**

### B-10. 메모리 누수 — 파이썬 측은 문제 없음

의뢰에서 지목한 항목이지만 확인 결과 **대부분 이미 방어되어 있다**:

- `threat_detector`의 `_ip_packet_window`/`_ip_port_window`/`_ip_byte_window`는 IP별 윈도우를 매 접근마다 필터링하고(`:232,247,262`), 추가로 주기적 stale IP 제거 루프가 있다(`:301-310`).
- `siem_correlation._by_ip`/`_by_type`은 `_prune()`이 빈 키까지 `del` 한다(`:132-141`).
- `mitre.recent`는 200개 절단(`:337`), `mitre.hits`는 택소노미로 유계.
- `deque(maxlen=...)`이 20개 모듈에 걸쳐 일관되게 쓰이고 있다.

**실제 무한 증가는 두 곳뿐이다**: (1) 디스크 — B-3, (2) `IncidentManager.incidents` 딕셔너리 — 23,299건 약 30MB가 시작 시 전량 메모리에 올라오고 절대 줄지 않는다(B-1/B-3와 같은 뿌리).

브라우저 측에는 진짜 누수가 하나 있다 — E-3 참조.

---

## C. 보안 하드닝

### C-1. [P0] CORS가 임의 Origin을 credentials와 함께 반영한다

**근거**: `app.py:62` — `CORS(app, supports_credentials=True)`

`origins`를 지정하지 않으면 flask-cors는 기본 `*`에 `supports_credentials=True`가 겹칠 때 **요청의 Origin을 그대로 반사**한다. 실제 앱을 띄워 검증했다:

```
GET /api/soar/status   Origin: https://evil.example
→ 200
   Access-Control-Allow-Origin: https://evil.example
   Access-Control-Allow-Credentials: true
   본문: {"actions":[],"approval_required":true,...,"blocked_ips":[...]}
```

**결과**: 분석가가 대시보드에 로그인한 상태로 임의의 웹사이트를 방문하면, 그 사이트의 스크립트가 세션 쿠키를 실은 채 88개 API 전부를 호출하고 **응답 본문을 읽을 수 있다**. 알림 이력, 차단 IP 목록, `/api/system/info`의 호스트 정보, `/api/system/public-ip`가 전부 유출된다.

`socketio`의 `cors_allowed_origins="*"`(`app.py:65`)도 같은 문제다. 소켓 연결은 세션을 검사하지만(`app.py:141`), 검사를 통과한 뒤에는 임의 Origin이 모든 실시간 이벤트를 구독한다.

**✅ 수정 완료** (`fix/p0-cors-csrf`, 2026-08-27): CORS 를 기본적으로 완전히 제거했다. 이 대시보드는 자기 페이지가 자기 API 를 부르는 동일 출처 앱이라 CORS 가 필요 없다. 별도 출처 클라이언트가 필요하면 `CORS_ORIGINS` 에 명시할 때만 활성화된다. SocketIO 의 `cors_allowed_origins` 도 `"*"` → 동일 목록(기본 빈 리스트 = 동일 출처만)으로 바꿨다.

검증: `Origin: https://evil.example` 요청에 `Access-Control-Allow-Origin` 이 더 이상 붙지 않는다. 회귀 테스트 `tests/test_security_hardening.py::test_cors_does_not_reflect_arbitrary_origin`.

### C-2. [P0] 상태변경 엔드포인트에 CSRF 방어가 없다

**근거**: POST/PUT/DELETE 라우트 40여 개, CSRF 토큰 검증 0건. 실측:

```
POST /api/soar/block   Origin: https://evil.example
Content-Type: application/json  {"ip":"203.0.113.9",...}
→ 200 (토큰 요구 없음)
```

`SESSION_COOKIE_SAMESITE = "Lax"`(`config.py:142`)가 단순 폼 POST는 막지만, **C-1이 이를 완전히 무력화한다** — Origin이 반사되므로 `fetch(..., {credentials:'include'})` 프리플라이트가 통과한다. 노출되는 것:

- `/api/soar/block`, `/api/soar/unblock` — 방화벽 규칙 조작
- `/api/edr/kill` — 프로세스 종료
- `/api/patch/command` — 원격 셸 명령 (C-3 참조)
- `/api/alerts/retention/run` — 알림 영구 삭제
- `/api/soar/approvals/batch` — 대기 중 차단 일괄 승인

**✅ 수정 완료** (`fix/p0-cors-csrf`, 2026-08-27):

- `SESSION_COOKIE_SAMESITE` 를 `Lax` → **`Strict`** 로 (외부 사이트가 시작한 요청에 쿠키를 아예 안 붙임).
- `before_request` 에 **Origin/Referer 검증**(`_require_same_origin`)을 추가. 상태변경 메서드(POST/PUT/DELETE/PATCH)는 출처가 자기 호스트여야 통과한다. OWASP 권고 방식이며, 프론트의 fetch 호출부 35곳을 **전혀 건드리지 않고** 적용된다(더블서밋 토큰은 35곳 수정이 필요했다).
- 인증 가드와 **분리**했다 — `AUTH_ENABLED=False` 여도 API 는 방화벽 조작·프로세스 종료 같은 특권 동작을 하므로 출처 검증은 계속 필요하다. (첫 구현에서 인증 가드 안에 넣었다가 인증 비활성 시 우회되는 것을 테스트로 잡았다.)
- `/login` POST 도 커버해 로그인 CSRF 를 막는다.

검증: 외부 Origin·외부 Referer·출처 헤더 없음 세 경우 모두 403, 동일 출처는 정상 통과. GET 은 CSRF 대상이 아니며 C-1 로 응답 열람이 막힌다. 회귀 테스트 7건.

### C-3. [P1] 파괴적 명령 blocklist가 실제로 우회된다

**근거**: `modules/patch_manager.py:28-32`(`_DANGEROUS_CMD`), `:405`(검사)

`/api/patch/command` → `run_command()` → `ansible -m shell -a <command>`(`:424`)로 원격 셸이 실행된다. 마지막 방어선이 부분 문자열 blocklist인데, 실행해서 확인했다:

```
차단  rm -rf /
통과  rm -fr /
통과  rm  -rf /                        ← 공백 하나
통과  rm -rf --no-preserve-root /
통과  find / -delete
```

**blocklist 방식 자체가 틀렸다.** `PATCH_APPLY_ENABLED=True`가 전제이고 현재 기본값은 `False`(`config.py:118`)라 즉시 위험은 아니지만, 이것이 **운영 중인 자동매매 서버**를 향한 마지막 게이트이며 C-2와 결합하면 원격에서 트리거된다.

**✅ 수정 완료** (`fix/p0-cors-csrf`, 2026-08-27): `check_command()` 로 **3중 방어**로 전환했다.

1. **셸 메타문자 차단** — `;` `&` `|` `` ` `` `$(` `${` `>` `<` 개행. 명령 연결·리다이렉션·치환 자체를 막는다.
2. **명령 allowlist** — 첫 토큰(basename 기준, `/bin/rm` 우회 차단)이 조회 전용 목록에 있어야 한다. 목록은 UI 플레이스홀더가 안내하는 용도("예: uptime · df -h · systemctl status trader")에서 도출했다. `PATCH_COMMAND_ALLOWLIST` 로 조정 가능.
3. **하위명령 제한** — `systemctl` 은 `status`/`is-active` 등 조회만. `restart`/`stop` 은 거부한다(운영 중 자동매매 프로세스를 원격에서 내리는 사고 방지). `apt`/`pip`/`dpkg` 도 동일.
4. 기존 blocklist 는 중복 방어로 유지.

부수 개선: dry-run 미리보기가 안전장치 판정을 함께 보여줘 '실행'을 누르기 전에 막힐 것을 알 수 있다.

검증: 감사에서 통과했던 4건(`rm -fr /`, `rm  -rf /`, `rm -rf --no-preserve-root /`, `find / -delete`)과 셸 이스케이프 9건 전부 차단, 정상 조회 명령 11건 전부 통과. 회귀 테스트 `tests/test_security_hardening.py` 에 우회 사례를 그대로 고정했다(이전엔 `_DANGEROUS_CMD` 검증 테스트가 0건이었다).

### C-4. [~~P2~~ **부분 수정**] 보안 헤더 전무

실측: `Content-Security-Policy`·`X-Frame-Options`·`X-Content-Type-Options`·`Strict-Transport-Security` **전부 `None`**.

CSP 부재가 특히 아프다 — C-6의 XSS 리스크에 대한 유일한 백스톱이 없다는 뜻이고, E-1의 CDN 9개 의존과 겹치면 CDN 하나가 오염될 때 막을 수단이 없다.

**⚠️ 부분 수정** (`feat/csp-vendor`, 2026-08-27): 헤더는 넣었으나 **CSP 가 XSS 를 막지 못한다.** 그 이유가 중요하다.

넣은 것:

| 헤더 | 값 | 효과 |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | MIME 스니핑 차단 |
| `X-Frame-Options` | `DENY` | 클릭재킹 |
| `Referrer-Policy` | `same-origin` | 대시보드 URL 이 외부로 새지 않음 |
| `Permissions-Policy` | 위치·마이크·카메라 차단 | 불필요 기능 최소화 |
| `Content-Security-Policy` | 아래 | 부분적 |

HSTS 는 의도적으로 넣지 않았다 — Tailscale HTTP 접속이라 걸면 접속 자체가 막힌다.

**CSP 의 한계 — `script-src` 에 `'unsafe-inline'` 이 들어간다.**

측정 결과 인라인 이벤트 핸들러가 템플릿에 **104개**, JS 가 생성하는 것이 **28개**, 인라인 `style=` 이 **486개**다. `'unsafe-inline'` 을 빼면 대시보드가 통째로 동작하지 않는다. 따라서 **이 CSP 는 C-6 의 XSS 백스톱 역할을 하지 못한다.** 132개 핸들러를 `addEventListener` 로 옮기는 리팩터링이 선행되어야 한다.

그럼에도 나머지 지시어는 실익이 있어 함께 넣었다:

```
object-src 'none'        플러그인/오브젝트 주입 차단
base-uri 'self'          <base> 주입으로 상대경로를 탈취하는 공격 차단
form-action 'self'       주입된 폼의 외부 제출 차단
frame-ancestors 'none'   클릭재킹 (CSP 판)
connect-src 'self' ws:   주입된 스크립트의 데이터 반출 대상 제한
```

`CSP_REPORT_ONLY=True` 로 보고 전용 전환, `CSP_EXTRA_SOURCES` 로 출처 추가가 가능하다.

테스트 10건. 그중 `test_csp_documents_its_own_weakness` 는 `'unsafe-inline'` 의 존재를 **명시적으로 고정**한다 — 나중에 리팩터링으로 제거하면 그 테스트가 실패하며 이 문서 갱신을 요구한다.

**남은 것**: 인라인 핸들러 132개 제거 (작업량 L) → 그 후 `'unsafe-inline'` 제거. E-1(CDN 자체 호스팅)을 하면 CDN 6개 호스트도 CSP 에서 뺄 수 있다.

### C-5. REST API 인증 가드 — 누락 없음 ✅

`app.py:80-91`의 `@app.before_request`가 전역이고, 공개 경로는 `/login`·`/logout`·`/static/*`뿐이다(`_is_public`, `:76`). 88개 엔드포인트 전부 커버된다. `api/` 어디에도 이를 우회하는 blueprint 수준 예외가 없다.

SocketIO도 `connect` 핸들러가 세션을 검사하고 `False`를 반환해 거부한다(`app.py:139-143`). **로그인 없이 이벤트 구독은 불가능하다.** 이 부분은 잘 되어 있다.

주의점 둘: `AUTH_ENABLED=False`면 전부 무방비인데(`app.py:59`에서 경고는 출력) 기본값이 `True`라 괜찮다. `SESSION_COOKIE_SECURE` 기본 `False`(`config.py:144`)는 Tailscale HTTP 환경에서는 타당한 선택 — 문서화만 되어 있으면 된다.

### C-6. [P2] XSS — 확증된 공격 경로는 없으나 방어가 불균질하다

**공격자가 제어하는 필드는 전부 이스케이프되어 있다**. 확인 결과:

| 필드 | 출처 | 렌더 |
|------|------|------|
| syslog `message` | 원격 전송단 | ✅ `escapeHtml` (`15-syslog.js:74`) |
| 허니팟 `payload` | 공격자 입력 | ✅ (`16-honeypot.js:61`) |
| 접근로그 `request` | HTTP 요청 라인 | ✅ (`06-sources.js:88`) |
| 프로세스 `cmdline` | EDR/Sigma | ✅ (`07-ops.js:151`, `06-sources.js:460`) |
| 퍼저 `payload`/`path` | 퍼징 대상 | ✅ (`07-ops.js:466-468`) |

이스케이프가 빠진 곳은 서버가 생성하는 열거형·카운터다:

```js
// static/js/dash/02-overview.js:256-259
<span class="rnk">#${i+1}</span>
<span class="ip">${ip}</span>              ← alert.src_ip
<span class="ttype">${info.type}</span>    ← alert.threat_type
```

`src_ip`는 파서들이 IP 정규식으로 추출하고 EDR은 운영자가 설정한 `EDR_HOST_LABEL`을 쓴다. **현시점에 악용 가능한 경로를 찾지 못했다** — 이 항목을 P2로 두는 이유다. 문제는 이것이 "안전하다"가 아니라 "우연히 안전하다"라는 점이다. 새 이벤트 소스가 `src_ip`에 자유 문자열을 넣는 순간 조용히 XSS가 된다.

**수정 방향**: C-4의 CSP를 먼저 넣고(백스톱 확보), 이후 `escapeHtml` 누락 지점을 기계적으로 채운다. **작업량 S**

### C-7. 커맨드 인젝션 표면 — 깨끗함 ✅

`shell=True` 0건, `os.system` 0건. 9개 `subprocess` 호출 전부 리스트 인자다.

- **ufw/iptables**: `_run_fw(["sudo","-n",helper,action,ip])`(`soar.py:816,825`). IP는 `_is_blockable`의 `ipaddress` 파싱을 통과한 것만 도달하고, helper가 다시 검증한다. 이중 방어.
- **nmap**: `addr`는 `ANSIBLE_TARGETS` 환경변수에서 파싱된 설정값이고, HTTP의 `host_ids`는 `_hosts_by_id()`(`vuln_scanner.py:201`)가 설정된 목록과 교집합만 취한다. 사용자 입력이 인자에 도달하지 않는다.
- **ansible**: `-a <command>`의 `command`만이 HTTP에서 직접 온다 → C-3.

`sigma_engine.py:420`의 `eval()`도 확인했다. `__builtins__` 제거 + `and|or|not|True|False|()`만 남는지 사전 검사 후 미해석 토큰이 있으면 `False` 반환(`:414-418`). **적절히 방어되어 있다** — 다만 `ast.literal_eval` 기반이나 수동 파서가 더 낫다는 원칙적 지적은 유효하다. P3.

### C-8. 시크릿 취급 — 양호 ✅

- `.env`는 git 미추적, `.gitignore:5`에 등재. `.env.example`만 커밋됨.
- 로그/API 응답에서 키 노출 검색 결과 0건. `/api/soar/virustotal/test`, `/api/notify/status` 등이 키 값이 아닌 `bool(api_key)` 형태의 활성 여부만 반환한다.
- `SECRET_KEY` 기본값 감지 시 랜덤 생성 + 경고(`app.py:29-35`), 비밀번호 미설정 시 임시 발급 후 콘솔 1회 표시(`app.py:47-56`). 잘 처리했다.
- `auth.py`: pbkdf2 해시, IP별 5회/300초 잠금, 평문 미저장. 커버리지 93%.

한 가지: `app.py:188`의 `allow_unsafe_werkzeug=True`. 개발 서버를 운영에 쓰겠다는 명시적 선언이다. 개인 포트폴리오/Tailscale 한정이면 수용 가능하나, `DEBUG=True`가 실수로 켜지면 Werkzeug 디버거(임의 코드 실행)가 노출된다. `.env`에서 `DEBUG`가 꺼져 있는지 배포 체크리스트에 넣을 것. **P3**

### C-9. 안전장치 회귀 테스트 현황

| 안전장치 | 테스트 |
|----------|--------|
| CGNAT/Tailscale 차단 금지 (경계값 포함) | ✅ `test_detection.py:473-481` |
| 화이트리스트 IP/접두 보호 | ✅ `:495-511` |
| 퍼저 사설 대상 제한 | ✅ `test_scanners.py:231-236` |
| `PATCH_APPLY_ENABLED` 게이트 | ✅ `test_detection.py:1011-1014` |
| 내부→외부 유출 allowlist | ✅ `:1317` |
| **`_DANGEROUS_CMD` blocklist** | ❌ **없음** → C-3 |
| **blocklist 파일 영속화/복원** | ❌ 없음 |
| **soc-ufw helper 스크립트 검증** | ❌ 없음 (셸이라 pytest 밖) |

---

## D. 테스트 / CI

### D-1. [P1] 커버리지 실측 — 전체 49%, API 계층 0%

`coverage run --source=modules,api,. -m pytest` 결과 (184 passed):

**커버리지 0%인 핵심 모듈**:

| 모듈 | Stmts | 비고 |
|------|-------|------|
| `api/` 전체 (7파일) | 627 | **88개 엔드포인트 전부 미검증** |
| `app.py` | 107 | 인증 가드·CORS·소켓 핸들러 미검증 |
| `wiring.py` | 150 | 배선 오류가 런타임까지 안 잡힘 |
| `modules/ml_analyst.py` | 315 | ML 파이프라인 전체 |
| `modules/ai_analyst.py` | 151 | AI 트리아지 전체 |
| `modules/packet_analyzer.py` | 203 | 패킷 수집 전체 |
| `modules/system_info.py` | 148 | |
| `modules/geoip.py` | 95 | |
| `modules/retention.py` | 64 | **삭제를 수행하는 코드가 무검증** |

`api/` 0%가 가장 아프다. 이 감사의 P0 두 건이 전부 API 계층 문제인데 회귀를 잡을 테스트가 없다. `retention.py` 0%는 **데이터를 영구 삭제하는 경로가 검증되지 않았다**는 뜻이라 별도로 심각하다.

낮은 쪽: `mitre_attack` 20%, `sysmon_parser` 26%, `threat_intel` 29%.
높은 쪽: `auth` 93%, `soc_metrics` 92%, `purple_team` 89%, `incidents` 85%.

**수정 방향**: `app.test_client()` 기반 API 스모크 테스트부터. 88개 엔드포인트에 대해 "200 또는 의도된 4xx를 반환하고 JSON이다"만 검사해도 0% → 60%대로 오르고, C-1/C-2 수정의 회귀 테스트를 얹을 자리가 생긴다. **작업량 L (단, 첫 30%는 M)**

### D-2a. [P1·신규·**수정됨**] 테스트가 실제 운영 설정으로 앱을 기동할 수 있었다

F-1 작업 중 발견했다. `tests/test_config_wiring.py` 가 모듈 레벨에서 `import config` 를 했는데, **pytest 는 수집 시점에 모든 테스트 모듈을 import 한다.** 그 시점에 `config.Config` 의 클래스 속성이 실제 `.env` 값으로 고정되고, 이후 앱을 띄우는 픽스처가 `os.environ` 을 바꿔도 반영되지 않았다.

결과적으로 테스트 스위트가 **사용자의 실제 설정으로 앱을 기동**했다:

```
[SOAR] 엔진 시작 — 차단 모드: ufw, 자동 차단: True
[SOAR] 실차단 활성 — ufw 방화벽 규칙을 실제 적용합니다.
[Honeypot] 유인 서비스 오픈: 100.64.140.27 ...
```

**실제 차단은 일어나지 않았다** — 테스트가 쓰는 IP 가 전부 `203.0.113.0/24`(RFC 5737 문서용)이고 `_is_blockable` 이 `is_global` 검사로 걸러냈다(`data/blocklist.txt` 0바이트 확인). 안전장치가 제 역할을 했다.

**수정**: (1) `test_config_wiring.py` 의 `import config` 를 함수 안으로 옮겨 수집 시점 오염을 없앴다. (2) 앱을 띄우는 두 픽스처가 `os.environ` 설정 후 `importlib.reload(config)` 를 하도록 해, 앞으로 어떤 모듈이 config 를 먼저 import 하더라도 격리가 유지된다.

이것은 감사가 아니라 **작업 중 제가 만든 문제**였고, 같은 작업의 테스트가 잡아냈다.

### D-2. [P2] `test_patch_check_runs` 환경 의존 flaky

**근거**: `tests/test_detection.py:1017-1027`

`demo=True`로 시작해도 `_execute_job`은 `self.ansible_bin`이 있으면 **실제 `ansible-playbook --check`를 실행**한다(`patch_manager.py:319-324`, 타임아웃 600s). 테스트는 `0.05s × 40 = 2초`만 기다린다. ansible이 설치된 이 환경에서 첫 실행은 실패(`assert 'running' in (...)`), 두 번째 실행은 통과했다 — 전형적인 타이밍 flake다.

**수정 방향**: `PatchManager`에 ansible 바이너리를 주입 가능하게 하고 테스트는 `ansible_bin=None`으로 시뮬레이션 경로를 강제. 또는 `demo=True`일 때 실제 subprocess를 타지 않도록. 후자가 "데모 fallback" 규칙에도 부합한다. **작업량 S**

### D-3. [~~P2~~ **수정됨**] CI 부재

`.github/` 디렉터리 자체가 없다. 제안:

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.10'}
      - run: pip install -r requirements.txt ruff pytest pip-audit coverage
      - run: ruff check --select E,F,I modules api app.py wiring.py config.py
      - run: coverage run --source=modules,api -m pytest -q
      - run: coverage report --fail-under=45   # 현재 49%, 하한부터
      - run: pip-audit -r requirements.txt
```

**✅ 수정 완료** (`ci/github-actions`, 2026-08-27): `.github/workflows/ci.yml` 신설.

- **잡 2개** — `test`(ruff + pytest + 커버리지 하한), `audit`(pip-audit).
- `audit` 은 `continue-on-error: true` 다. 신규 CVE 공개로 빨간불이 되어도 테스트 잡을 막지 않되, 보안 도구인 만큼 결과는 보이게 유지한다.
- 커버리지 하한 **70%** (실측 74%). 내려가지 않게만 막고 목표는 점진적으로 올린다.
- 차단 경로를 `SOAR_BLOCK_MODE=simulate` 로 고정해 CI 가 어떤 경우에도 방화벽을 건드리지 않게 했다.

**검증 방식**: 워크플로를 눈으로 읽는 대신, `git archive` 로 **추적 파일만 뽑아 `.env` 없는 fresh clone 상태를 만들고** CI 가 실행할 명령을 그대로 돌렸다. 결과: ruff 통과, pytest 436건 통과, 커버리지 74%.

D-2(flaky)는 이미 해소돼 있어 CI 도입을 막지 않았다.

### D-4. [~~양호~~ **정정 · 수정됨**] 의존성 고정값이 실제와 달랐다

**초판의 "의존성 고정 — 양호"는 오판이었다.** `==` 고정이 있는지만 보고 그 값이 실제 설치 버전과 맞는지 확인하지 않았다. B-4 작업 중 SDK 버전을 확인하다 드러났다.

실측 (2026-08-27, 나열된 14개 중):

| 상태 | 수 | 예 |
|---|---|---|
| 불일치 | **10** | `numpy` 1.26.4 고정 / **2.2.6** 설치 (메이저 차이), `anthropic` 0.40.0 / **0.116.0** |
| 미설치 | 3 | `pyshark`, `scapy`(실환경 전용), `python-dateutil`(**사용처 0건**) |
| 일치 | 1 | `PyYAML` |

**의미**: fresh clone 에서 `pip install -r requirements.txt` 를 하면 **이 저장소의 테스트가 한 번도 통과해 본 적 없는 조합**을 받는다. 포트폴리오로서 치명적이다 — 리뷰어가 클론하면 다른 환경을 얻는다.

**✅ 수정 완료** (`fix/ai-resilience`): 고정값을 실제 검증된 조합(pytest 379건 통과)으로 갱신했다. `pyshark`/`scapy`/`tensorflow` 는 데모 fallback 이 있으므로 선택 사항으로 주석 처리하고 그 사실을 파일에 적었다. 사용처가 0건인 `python-dateutil` 은 제거했다.

**남은 것**: `pip-audit` 는 여전히 실행하지 않았으므로 취약 패키지 여부는 단정할 수 없다. D-3 의 CI 에 포함시킬 것.

참고로 모델 ID `claude-sonnet-4-6`(`ai_analyst.py:39`)은 **유효한 현행 모델이다** (1M 컨텍스트, $3/$15 per MTok). 문서와도 일치한다 — 수정 불필요. 다만 `claude-sonnet-5`가 더 저렴하고($2/$10) 컨텍스트가 같으므로 전환을 검토할 가치는 있다.

---

## E. 프론트엔드

### E-1. [P2] CDN 9개 · SRI 없음 · 오프라인 불가

**근거**: `templates/dashboard.html:252-261`

bootstrap, chart.js, leaflet, jquery, datatables(×2), socket.io, three.js, globe.gl — **9개 외부 스크립트에 `integrity` 속성이 하나도 없다.** jsdelivr/unpkg/cdn.datatables.net/code.jquery.com 4개 도메인이 오염되면 대시보드에 임의 코드가 실행된다. CSP도 없어(C-4) 백스톱이 없다.

동시에 **격리망에서 이 대시보드는 동작하지 않는다.** SOC 도구가 인터넷 없이 못 뜬다는 건 배포 시나리오상 뼈아프다.

**수정 방향**: 라이브러리를 `static/vendor/`로 내려받아 자체 호스팅. 부수적으로 CSP를 `script-src 'self'`로 조일 수 있게 된다. 용량은 three.js+globe.gl 때문에 약 1.5MB 늘지만 그만한 값어치가 있다. **작업량 S**

### E-2. [P3] 전역 네임스페이스 오염 · 로드 순서 의존

18개 파일이 `<script>` 태그로 순서대로 로드되고, 최상위 선언이 **323개**다(`06-sources.js` 47개, `07-ops.js` 56개가 최다). 모듈 시스템이 없으므로:

- `01-core.js:20`의 `const socket = io()`를 나머지 17개 파일이 전역으로 참조한다. `01`이 먼저 와야 한다는 계약이 파일명 숫자에만 의존한다.
- `escapeHtml`, `sevBadge`, `pushLive`, `isPanelVisible` 같은 공용 함수도 전역. 어느 파일이 정의하는지 grep 없이는 알 수 없다.
- 같은 이름을 두 파일이 `let`으로 선언하면 **로드 시점에 SyntaxError로 대시보드 전체가 죽는다**. 현재 충돌은 없지만 새 패널을 추가할 때마다 이 위험을 감수하는 구조다.

**수정 방향**: `<script type="module">` + `import`로 전환. 다만 이건 18개 파일 전부를 건드리는 대공사이고 얻는 것이 안전성뿐이다. **지금은 하지 말 것.** 현실적 대안은 각 파일을 IIFE로 감싸고 `window.SOC = {}` 네임스페이스에 공개 함수만 노출하는 것 — 점진적이고 파일당 독립 적용 가능하다. **작업량 L (모듈화) / M (IIFE 점진)**

### E-3. [P3] `_attackerCounter` 무한 증가 + 알림마다 전량 정렬

**근거**: `static/js/dash/02-overview.js:101-105`

```js
_attackerCounter[alert.src_ip] = _attackerCounter[alert.src_ip] || {...};
_attackerCounter[alert.src_ip].count++;
document.getElementById('kpi-unique-attackers').textContent = Object.keys(_attackerCounter).length;
if (isPanelVisible('overview') && !document.hidden) renderTopAttackers();
```

고유 공격 IP마다 항목이 추가되고 **절대 정리되지 않는다**. 브라우저 탭을 며칠 열어두는 관제 시나리오에서 이건 진짜 누수다. 게다가 `renderTopAttackers()`가 매 알림마다 전체를 `sort()` 한다(`:538` 계열) — O(n log n) × 알림 수.

`_threatTypeCounter`(`:108`)도 같지만 위협 유형은 유계라 무해하다.

**수정 방향**: `_attackerCounter`에 상한(예: 500 IP, LRU 절단)을 두고, `renderTopAttackers`를 라이브 스트림처럼 300ms 스로틀. **작업량 S**

### E-4. DOM 성능 — 이미 상당히 방어되어 있다 ✅

의뢰의 우려와 달리 폭주 대비가 되어 있다:

- 라이브 스트림: `_liveBuffer`가 `LIVE_MAX`로 유계, 렌더는 300ms 배치 스로틀(`02-overview.js:160-162`), 표시는 상위 60건만(`:174`).
- 패널이 숨겨져 있거나 `document.hidden`이면 렌더 생략(`:88-89`, `:169-171`) — CPU 절약이 일관되게 적용됨.
- syslog 버퍼 500 절단 + 표시 200 절단(`15-syslog.js:84,92`).
- 접근로그 패널은 `requestAnimationFrame` 스로틀(`06-sources.js:171` 주석).

**가상 스크롤은 필요 없다** — 표시 건수 자체를 절단하고 있어서다. 남은 문제는 E-3 하나뿐이다.

### E-5. SocketIO 핸들러 — 중복 등록 없음 ✅

`socket.on(...)` 등록을 이벤트명으로 집계한 결과 **전부 1회**. 핸들러가 패널 전환 시점이 아니라 파일 로드 시점에 한 번만 등록되는 구조라 누수가 없다. 이 부분은 설계가 옳다.

---

## F. 문서 / 저장소 위생

### F-1. [~~P2~~ **수정됨**] 문서화된 탐지 임계값이 코드에서 죽어 있다

가장 실질적인 문서-코드 불일치다. `config.py`·`README.md`·`CLAUDE.md`가 튜닝 노브로 소개하는 변수들이 **어디에서도 읽히지 않는다**:

| 변수 | 문서상 기본값 | 코드 실제 |
|------|--------------|-----------|
| `DDOS_PACKET_THRESHOLD` | 1000 pps | **`avg_pps > 2000` 하드코딩** (`threat_detector.py:236`) |
| `PORT_SCAN_THRESHOLD` | 20 포트/초 | **`unique_ports >= 40` 하드코딩** (`:251`) |
| `DDOS_BYTE_THRESHOLD` | 10 MB/s | 사용처 없음 |
| `MAX_PACKETS_DISPLAY` | 200 | `deque(maxlen=200)` 하드코딩 (`packet_analyzer.py:45`) |
| `CAPTURE_TIMEOUT` | 30 | 사용처 없음 |
| `DEMO_UPDATE_INTERVAL` | 2.0 | 사용처 없음 |
| `SYSMON_LOG_CHANNEL` | — | 사용처 없음 |
| `WINDOWS_EVENT_LOG_MAX` | 100 | 사용처 없음 |

`.env`에서 임계값을 조정한 운영자는 **아무 일도 일어나지 않는데 그 사실을 알 방법이 없다.** 문서화된 기본값(1000/20)과 실제 동작(2000/40)이 2배씩 다르다는 점도 문제다.

역방향도 있다: `siem_correlation.py`가 읽는 `SIEM_CORR_WINDOW`·`SIEM_CORR_BRUTE`·`SIEM_CORR_DISTRIBUTED`·`SIEM_CORR_MULTIVECTOR`·`SIEM_CORR_COOLDOWN` 5개는 **`config.py`에도 `.env.example`에도 없다.** `config.get()`이 조용히 기본값으로 떨어지므로 설정 자체가 불가능하다.

**✅ 수정 완료** (`fix/dead-config`, 2026-08-27):

연결한 것 — `DDOS_PACKET_THRESHOLD`, `PORT_SCAN_THRESHOLD`, `MAX_PACKETS_DISPLAY`, `DEMO_UPDATE_INTERVAL`, `SYSMON_LOG_CHANNEL`.

**기본값은 문서값(1000/20)이 아니라 실제 동작하던 값(2000/40)으로 맞췄다.** 문서값으로 되돌리면 탐지 민감도가 조용히 2배 올라간다 — 운영 중인 서버에서 그건 배선을 고치는 것보다 위험한 변경이다.

삭제한 것 — 자연스러운 연결 지점이 없어 죽은 채로 두느니 제거했다. 없는 용도를 억지로 만드는 것이 더 나쁘다.
- `DDOS_BYTE_THRESHOLD`: 바이트 기준 DDoS 검사 자체가 코드에 없다.
- `CAPTURE_TIMEOUT`: `scapy.sniff(timeout=)` 은 캡처를 *중단*시켜 지속 캡처와 의미가 맞지 않는다.
- `WINDOWS_EVENT_LOG_MAX`: 의미가 모호하고(폴링당 레코드 수? 보관 수?) 대응하는 코드가 없다.

역방향으로 추가한 것 — 모듈이 읽는데 `config.py` 에 없어 `.env` 로 설정할 수 없던 값들: `SIEM_CORR_*` 5개, `PATCH_COMMAND_ALLOWLIST`, `AUDIT_DB`, `WATCHLIST_DB`.

**재발 방지** (`tests/test_config_wiring.py`) — 양방향 회귀 테스트를 넣었다.
- 선언됐는데 안 읽히는 설정이 있으면 실패 (F-1 의 본체)
- 모듈이 읽는데 선언 안 된 설정이 있으면 실패 (역방향)
- 두 방향에 **서로 다른 추출 규칙**을 쓴다. 전자는 리터럴 전역 검색(헬퍼 경유 참조를 놓치지 않기 위해), 후자는 `config…get("KEY")` 접근 구문만(감사 액션명 `SOAR_BLOCK` 같은 설정 아닌 상수를 배제하기 위해).
- 이 테스트가 실제로 `AUDIT_DB`·`WATCHLIST_DB`·`PATCH_COMMAND_ALLOWLIST` 누락을 잡아냈다.

⚠️ **운영자 확인 필요**: 로컬 `.env` 에 `DDOS_PACKET_THRESHOLD=1000` / `PORT_SCAN_THRESHOLD=20` 이 들어 있다. 지금까지는 무시됐지만 이제 **실제로 적용된다** — 재시작하면 탐지 민감도가 2배가 된다. 기존 동작을 유지하려면 `.env` 를 2000/40 으로 바꿔야 한다. (`.env` 는 사용자 파일이라 임의로 수정하지 않았다)

### F-2. [P2] `.env.example`이 config.py를 커버하지 못한다

87개 변수 중 **25개 누락**:

```
ABUSEIPDB_CACHE_HOURS  ABUSEIPDB_MIN_SCORE  CAPTURE_TIMEOUT
DATA_RETENTION_INTERVAL_HOURS  DDOS_BYTE_THRESHOLD  DEMO_UPDATE_INTERVAL
EDR_HOST_LABEL  EDR_SCAN_INTERVAL  FUZZ_ALLOW_WRITE  FUZZ_TIMEOUT
MALICIOUS_HASH_DB  MAX_PACKETS_DISPLAY  NET_MONITOR_INTERVAL  NTFY_COOLDOWN
NTFY_SERVER  NTFY_TOKEN  PATCH_PLAYBOOK_DIR  REPORT_DIR  SESSION_COOKIE_SECURE
SIGMA_RULES_DIR  SYSMON_LOG_CHANNEL  VIRUSTOTAL_CACHE_HOURS  VIRUSTOTAL_TIMEOUT
VULN_SCAN_PORTS  WINDOWS_EVENT_LOG_MAX
```

이 중 `FUZZ_ALLOW_WRITE`와 `SESSION_COOKIE_SECURE`는 **보안 관련 토글인데 문서화되지 않았다** — 특히 아쉽다.

반대로 `ANTHROPIC_API_KEY`는 `.env.example`에만 있고 `config.py`에는 없다. `ai_analyst.py:38`이 `os.getenv`로 직접 읽는 구조라 동작은 하지만, 설정 일원화 원칙에서 벗어나 있다.

**수정 방향**: F-1의 정리 후 `.env.example`을 config.py에서 생성하고, CI에 두 파일 동기화 검사를 추가. **작업량 S**

### F-3. [P2] README 수치 불일치

| README 주장 | 실제 |
|-------------|------|
| "34개 모듈" (`:14`, `:206`) | **40개** (`modules/*.py` minus `__init__`) |
| "약 11,000 LOC" (`:14`) | **13,183** (modules+api, 테스트 2,211 별도) |
| "pytest 153개" (`:164`, `:219`) | **184개** |
| CLAUDE.md "패널 31개" | **33개** |
| CLAUDE.md "`01~16-*.js`" | **`01~18-*.js`** |

기능 자체는 전부 존재한다 — 없는 기능을 주장하는 곳은 찾지 못했다. 단순히 문서가 코드 성장을 못 따라온 것이다. 포트폴리오 문서에서 수치가 실제보다 **작게** 적혀 있는 건 손해이기도 하다.

### F-4. [P3] 저장소명 오타 `AI-SOC-DaschBoard`

`git remote -v` → `https://github.com/MintKangaroo/AI-SOC-DaschBoard.git`

**영향 범위 조사 결과 — 리네임은 안전하다**:

- 로컬 디렉터리명은 이미 `SOC_DashBoard`로 올바름. 저장소명만 오타.
- 코드·문서·설정 어디에도 `DaschBoard` 문자열이 하드코딩된 곳이 **0건**.
- GitHub이 리네임 후 구 URL을 자동 리다이렉트하므로 기존 clone도 계속 동작한다.
- 필요한 후속 작업은 `git remote set-url origin ...` 한 줄뿐.

포트폴리오 저장소에서 이름 오타는 첫인상에 직접 영향을 준다. **비용 대비 효과가 가장 좋은 항목이다.** **작업량 S**

### F-5. [P3] Dockerfile · GitHub 메타데이터 부재

`Dockerfile`·`docker-compose.yml` 없음. 데모 실행이 "venv 만들고 pip install하고 .env 쓰고 python app.py" 4단계다. 포트폴리오 관점에서 `docker compose up` 한 줄로 뜨는 것과는 인상 차이가 크다.

다만 주의: 이 앱은 **호스트 네트워크·`sudo ufw`·`/var/log/auth.log`·psutil 프로세스 스캔**에 의존한다. 컨테이너화하면 실모드 기능 상당수가 데모로 떨어진다. 그래도 `DEMO_MODE=True` 전용 "데모 컨테이너"로 한정하면 가치가 있다 — **목적을 데모로 명시**해야 한다.

GitHub About/topics 비어 있음은 코드 밖 작업이라 감사 범위 밖이지만, `security`, `soc`, `siem`, `soar`, `flask`, `mitre-attack`, `threat-detection` 정도를 권한다.

---

## 3분류: 지금 / 나중 / 안 함

### 지금 고칠 것 (승인 시 이 순서로)

| 순 | 항목 | 근거 | 작업량 |
|----|------|------|--------|
| 1 | **C-1 CORS Origin 반영 차단** | 실증된 P0, 한 줄 수정 | S |
| 2 | **D-1 API 스모크 테스트 골격** | 이후 모든 수정의 안전망. 0% → 60% | M |
| 3 | **C-3 파괴적 명령 allowlist 전환 + 회귀 테스트** | 우회 실증됨, 대상이 운영 서버 | S |
| 4 | **C-2 CSRF (SameSite=Strict + 헤더 검사)** | C-1 이후 잔여 위험 차단 | M |
| 5 | **C-4 보안 헤더 4종** | C-6의 백스톱 확보 | S |
| 6 | **B-1+B-2 인시던트 dirty-set 저장** | 탐지 경로 블로킹 + 32,766 상한 동시 해소 | M |
| 7 | **B-4 Anthropic 타임아웃 + 챗봇 비동기화** | 30분 스톨 제거 | S |
| 8 | **F-1 임계값 env 연결 + 문서 정정** | 보안 도구 신뢰도 직결 | S |
| 9 | **B-3 incidents/soar_executions 보존정책** | 66MB 무한 증가 | M |
| 10 | **D-2 flaky 테스트 + D-3 CI** | 위 수정들을 지속 검증 | M |

### 나중에 할 것

- **A-3** API 에러 핸들러 + 응답 스키마 통일 (프론트 동시 수정 필요)
- **B-5** 허니팟/syslog 연결 세마포어 (`HONEYPOT_BIND=0.0.0.0` 전환 **전에는 반드시**)
- **B-7** alert_store WAL + 읽기 전용 커넥션 분리
- **B-9** `print()` → `logging` 일괄 전환
- **E-1** CDN 자체 호스팅 (C-4의 CSP를 `'self'`로 조일 때 함께)
- **E-3** `_attackerCounter` 상한 + 렌더 스로틀
- **A-5** `ruff` 도입 + A-4 미사용 import 40건 정리
- **F-2/F-3** `.env.example` 동기화, README 수치 정정
- **F-4** 저장소 리네임 (안전 확인됨, 언제든)
- **D-4** `pip-audit` 실행 후 판단

### 안 고쳐도 되는 것

- **`wiring.py` 리팩터링** — composition root로서 올바른 형태다. 건드리면 나빠진다.
- **`sigma_engine.py:420`의 `eval()`** — 사전 토큰 검증 + `__builtins__` 제거로 충분히 방어됨. 수동 파서로 바꾸는 건 순수 비용.
- **`E-4` 가상 스크롤 도입** — 표시 건수를 절단하는 현 방식이 더 단순하고 이미 충분하다.
- **`E-2` ES 모듈 전면 전환** — 18파일 전부를 건드리는데 얻는 게 안전성뿐. IIFE 점진 적용으로 대체.
- **`mypy` 도입** — 타입힌트 1.2% 상태에서는 소음만 생산한다. 새 코드에만 적용.
- **모듈 40개 통폐합** — 중복이 실제로 없다. 개수는 문제가 아니다.
- **`SESSION_COOKIE_SECURE=False`** — Tailscale HTTP 환경에서 타당한 선택. 문서화만 하면 됨.
- **`allow_unsafe_werkzeug=True`** — 개인 프로젝트 + Tailscale 한정이면 수용 가능. 단 `DEBUG=False` 확인은 배포 체크리스트에.
- **컨테이너화** — 실모드 기능 대부분이 호스트 의존이라 컨테이너에서 데모로 떨어진다. 데모 목적으로 명시할 때만 가치 있음.

---

## 3단계 — 기능 개선 제안

### 제안하신 7개에 대한 판정

#### 1. 로그 스키마 정규화 (OCSF 또는 ECS) — **비추천 (현 형태로는)**

반대한다. 이유는 셋이다.

첫째, **모듈 간 이벤트 포맷은 이미 통일되어 있다.** 모든 탐지 소스가 `threat_detector.report_alert()`라는 단일 진입점을 지나고, `alert_store`의 스키마(`threat_type`/`severity`/`src_ip`/`dst_ip`/`description`/`details`/`origin`/`verdict`)가 사실상의 내부 정규 스키마 역할을 하고 있다. 해결할 문제가 이미 해결되어 있다.

둘째, **OCSF는 무겁다.** OCSF 이벤트 하나는 중첩 객체 수십 필드다. 40개 모듈의 이벤트를 전부 OCSF 클래스에 매핑하는 작업량이 L이고, 그 대가로 얻는 건 "표준을 따른다"는 사실뿐이다 — 이 대시보드는 다른 시스템과 이벤트를 교환하지 않는다.

셋째, 포트폴리오 관점에서도 **보이지 않는다.** 화면에 아무 변화가 없다.

**대안**: 정말 필요한 건 스키마 표준화가 아니라 **내보내기(export) 계층**이다. `/api/alerts/history/export.csv`가 이미 있으니 여기에 OCSF JSON 내보내기를 **한 개 엔드포인트로** 추가하면, "표준 포맷 상호운용성"을 시연하면서도 내부 구조는 건드리지 않는다. 작업량 S. 이쪽을 권한다.

#### 2. Sigma 룰 CI 검증 (detection-as-code) — **강력 추천**

이 목록에서 가장 좋은 아이디어다.

- **기반이 이미 있다.** `sigma_engine.py`(488 LOC, 커버리지 75%)와 `purple_team.py`(7개 시나리오, 커버리지 89%)가 존재한다. 퍼플팀 하네스는 이미 "공격 시뮬레이션 → 탐지 검증"을 하고 있다 — CI로 옮기기만 하면 된다.
- **D-3의 CI 워크플로에 자연스럽게 얹힌다.** 룰 문법 검증 + 샘플 로그 기반 탐지 어서션을 pytest로 쓰면 기존 테스트 인프라를 그대로 쓴다.
- **포트폴리오 가치가 크다.** "탐지 룰을 코드로 관리하고 CI에서 회귀 검증한다"는 실무 SOC에서도 성숙도가 높은 축에 속하는 실천이다. README에 배지 하나로 드러난다.

**단, D-3(CI 자체)이 선행되어야 한다.** 작업량 M.

#### 3. 알림 중복제거/집계 (dedup·suppression) — **부분 구현됨 → 보완 추천**

이미 있는 것: `alert_store.grouped_recent(hours, min_count, limit)`(`:301`)과 `/api/alerts/groups`가 유사 알림을 묶고, `honeypot`의 `HONEYPOT_COOLDOWN`(동일 IP 재알림 간격), `notifier`의 `NTFY_COOLDOWN`, `siem_correlation`의 `SIEM_CORR_COOLDOWN`이 소스별 억제를 한다.

없는 것: **파이프라인 레벨의 통합 억제.** 현재는 각 모듈이 자기만의 쿨다운을 갖고 있어서, 같은 IP가 syslog·허니팟·Snort에 동시에 걸리면 알림 3건이 각각 생성된다. 인시던트 23,299건이라는 숫자가 그 증거다.

**추천하되 범위를 좁힐 것**: `threat_detector._add_alert()`에 `(threat_type, src_ip)` 키의 억제 윈도우를 하나 추가하고, 억제된 건은 기존 알림의 `details["suppressed_count"]`를 증가시키는 방식. 작업량 S~M. 이건 B-3(인시던트 무한 증가)의 근본 원인 완화이기도 하다.

#### 4. 케이스 타임라인 뷰 + 조사 노트 — **대부분 구현됨 → 비추천**

`incidents.py`에 이미 다 있다:

- 타임라인: `inc["timeline"]`에 `open`/`alert`/`block`/`enrich` 종류별 항목이 쌓인다(`:74,85,90,110`).
- 조사 노트: `alert_store`에 `note`·`assignee` 컬럼(`:32-33`), `verdict`/`verdict_actor`/`verdict_reason`/`verdict_at`(`:51-55`), `/api/alerts/<id>/verdict`가 근거 3자 이상을 강제한다.
- 감사: `audit_log`가 모든 조치를 append-only로 기록.

남은 건 **UI 노출**뿐이다. 데이터는 다 있는데 `templates/panels/incidents.html`이 이를 얼마나 보여주는지가 문제다. 새 기능이 아니라 기존 데이터의 렌더링 개선이므로, "신규 기능 후보"에서는 빼는 게 맞다. 작업량 S로 별건 처리 권장.

#### 5. SQLite → Postgres/TimescaleDB — **비추천**

강하게 반대한다.

- **현재 병목이 SQLite가 아니다.** B-1에서 측정했듯 느린 건 "23,299건을 매번 전량 재직렬화하는 애플리케이션 코드"다. Postgres로 옮겨도 전량 재작성하면 똑같이 느리다. **잘못된 계층을 고치는 것이다.**
- **규모가 안 맞는다.** 최대 테이블이 110,748행이다. SQLite는 이 규모에서 전혀 힘들지 않다.
- **배포 복잡도가 급증한다.** 단일 파일 → 별도 서버 프로세스. 개인 홈서버 포트폴리오의 "clone하고 실행하면 뜬다"는 장점을 잃는다.
- **포트폴리오 가치도 낮다.** "Postgres를 씁니다"는 차별점이 아니다.

**먼저 B-1/B-3을 고치고, 그 후에도 병목이 남으면 그때 재논의하자.** 십중팔구 안 남는다.

#### 6. Claude 분석 결과의 근거 추적 (프롬프트·응답 감사 로그) — **추천**

찬성한다. 근거:

- 현재 `ai_analyst.analysis_history`는 `deque(maxlen=100)`(`:43`)로 **메모리에만** 있다. 재시작하면 사라진다. AI가 CRITICAL 알림을 오탐 판정한 근거를 사후에 확인할 방법이 없다.
- SOAR가 AI 판정을 차단 결정에 쓴다(`wiring.py:66`). **자동 차단의 근거가 휘발성**이라는 건 운영상 결함에 가깝다.
- `audit_log`(append-only)라는 딱 맞는 인프라가 이미 있다. `audit.record(actor="ai_analyst", action="TRIAGE", target=alert_id, detail=...)` 형태로 얹으면 된다.
- 포트폴리오 관점에서 "AI 판단의 감사 추적성"은 지금 실무에서 실제로 요구되는 주제다.

**단, 프롬프트 전문 저장은 신중히.** 프롬프트에 `src_ip`·`description` 등 알림 내용이 들어가므로 사실상 알림 사본이 생긴다. **모델 ID·토큰 사용량·응답 요약·판정 결과·프롬프트 해시**만 저장하고 전문은 옵션으로. 작업량 S~M.

#### 7. 위협 헌팅 쿼리 콘솔 (저장된 쿼리 실행) — **조건부 추천**

가치는 인정하나 **선행 조건이 있다.**

가치: `alert_store.search()`가 이미 8개 조건(severity/status/threat_type/verdict/origin/ip/text/날짜범위)을 지원하고 `/api/alerts/history`로 노출되어 있다. 여기에 "쿼리 저장 + 재실행 + 워치리스트 연동"을 얹는 건 자연스럽고, `watchlist.py`가 IOC 헌팅 매칭을 이미 한다. 시연 효과도 좋다.

선행 조건 — **F-1의 P2 항목(D-13)을 먼저 풀어야 한다**: `search()`는 `alerts` 테이블만 조회하고 `archive.alerts_archive`의 **110,748건은 건드리지 않는다**(`alert_store.py:202-212`). 헌팅 콘솔을 만들어도 조회 대상이 활성 99건뿐이라면 의미가 없다. `search()`에 `include_archive` 옵션을 추가하는 게 먼저다(그 김에 `:174`의 "전체 DB 대상"이라는 잘못된 docstring도 고칠 것).

**순서**: 아카이브 조회 지원(M) → 헌팅 콘솔(M). 둘 다 하면 가치 있고, 후자만 하면 껍데기다.

---

### 추가 제안 3개

#### A. 탐지 커버리지 자가 진단 (Detection Coverage Gap Report) — **최우선 추천**

MITRE ATT&CK 14 Tactic × Technique 매트릭스를 이미 갖고 있고(`mitre_attack.py`, 443 LOC), Sigma 룰 5개, 퍼플팀 시나리오 7개가 있다. 그런데 **"우리가 무엇을 탐지하지 못하는가"를 답하는 화면이 없다.**

만들 것: 각 Technique에 대해 `(A) 탐지 룰이 존재하는가` × `(B) 퍼플팀 시나리오로 검증되었는가` × `(C) 실제 히트가 있었는가` 3축을 매트릭스에 색으로 겹쳐 표시. 룰도 없고 검증도 없는 셀이 곧 **커버리지 공백**이다.

왜 최우선인가:
- **기존 데이터만으로 만들어진다.** `mitre_tracker.hits`, `sigma.rules`의 `tags`, `purple.scenarios`의 technique 매핑을 조인하면 끝. 새 수집기가 필요 없다.
- 제안 #2(Sigma CI)와 직결된다 — 공백 셀이 곧 다음에 써야 할 룰의 목록이 된다.
- **실무 SOC 성숙도 평가의 표준 산출물**이다. 포트폴리오에서 "탐지를 만들 줄 안다"를 넘어 "탐지 프로그램을 운영할 줄 안다"로 올라간다.
- 스크린샷 한 장으로 설명된다.

작업량 M.

#### B. 자기 관측성 대시보드 (Self-Telemetry) — **추천**

B-9(로깅), B-6(스레드 생명주기), B-4(외부 API 지연)에서 반복해 드러난 문제: **이 SOC 도구는 자기 자신을 관측하지 못한다.** `system_health.py`가 모듈의 real/demo/off 상태를 보여주지만, "AI 큐가 얼마나 밀렸나", "AbuseIPDB 응답이 몇 ms인가", "인시던트 저장이 몇 초 걸리나", "억제된 알림이 몇 건인가"는 알 수 없다.

만들 것: 각 모듈이 `get_health()`에 처리 지연·큐 깊이·에러 카운트·마지막 성공 시각을 추가로 보고하고, 헬스 패널에 시계열로 표시. B-9(구조화 로깅)의 자연스러운 후속이다.

이건 단순히 있으면 좋은 게 아니라, **이 감사에서 발견한 문제 대부분이 관측성이 있었다면 스스로 드러났을 것들이다.** B-1의 0.63초 저장 지연, B-2의 무성 실패, B-4의 30분 스톨 — 전부 그렇다.

작업량 M.

#### C. 차단 결정 재현 로그 (Block Decision Replay) — **추천**

SOAR가 IP를 차단할 때 신뢰도·AI 판정·IP 평판·상관관계·Snort SID 품질·ML 점수가 모두 관여한다(`soar.py`, `decision_support.py`). 하지만 **사후에 "왜 이 IP가 차단되었나"를 완전히 재구성할 수 없다.** `soar_executions.db`에 스냅샷은 있으나 각 입력 신호의 그 시점 값이 없다.

만들 것: 차단 결정 시점의 모든 입력 신호를 하나의 결정 레코드로 고정하고, UI에서 "이 결정에 각 신호가 얼마나 기여했는가"를 분해해 보여준다. 나아가 임계값을 바꿨다면 결과가 달라졌을지 **재생(replay)** 한다.

왜 좋은가:
- 제안 #6(AI 근거 추적)의 상위 집합이고, 자동 차단이라는 **되돌리기 어려운 조치**에 설명책임을 부여한다.
- `SOAR_MIN_BLOCK_CONFIDENCE` 같은 임계값을 실데이터로 튜닝할 근거가 생긴다.
- 이미 `decision_support.py`가 클러스터 prior를 학습하고 있어 절반은 있다.
- 실무에서 자동 차단의 최대 장애물이 "왜 차단됐는지 설명 못 함"이다. 이걸 푸는 화면은 설득력이 있다.

작업량 M~L. #6보다 크지만 #6을 포함한다 — 둘 중 하나만 한다면 이쪽.

---

## 다음 단계

승인해 주시면 **"지금 고칠 것" 1번(C-1 CORS)부터 한 항목씩** 진행하겠습니다. 항목마다 커밋을 분리하고 매번 `pytest`를 돌립니다. 대규모 리팩터링은 하지 않습니다.

다만 순서에 대해 한 가지 확인이 필요합니다. 목록에서 **2번(API 스모크 테스트)을 1번 다음에 둔 이유**는, 이후 P0/P1 수정이 전부 API 계층을 건드리는데 커버리지가 0%라 회귀를 잡을 수단이 없기 때문입니다. 다만 이건 "보안 구멍을 먼저 막자"보다 느린 길입니다. 두 가지 중 선택해 주십시오.

- **(a) 안전망 우선** — C-1 → D-1(테스트) → C-3 → C-2 → ... (권장)
- **(b) 구멍 우선** — C-1 → C-3 → C-2 → C-4 → 그 다음 D-1

또 하나: **C-3(파괴적 명령 allowlist 전환)에서 허용할 명령 목록**을 정해야 합니다. 현재 이 기능을 실제로 어떤 용도로 쓰고 계신지(예: `apt` 조회, `systemctl status`, 로그 확인) 알려주시면 그에 맞춰 화이트리스트를 짜겠습니다. 모르는 상태로 추측해서 짜면 필요한 명령이 막히거나 불필요하게 넓어집니다.
