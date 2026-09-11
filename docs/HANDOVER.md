# 인수인계 — 2026-09-09 기준

이 문서는 "지금 어디까지 됐고, 무엇이 돌아가고 있고, 무엇을 결정해야 하는가"만 적는다.
설계·근거는 [README](../README.md)·[architecture](architecture.md)·[CLAUDE.md](../CLAUDE.md)에 있다.

## Codex 작업 교통정리 · 최신 단계 (2026-09-11)

09-09 저녁의 Codex 커밋 3건(TRACE 콘솔 `8dba946`, 역할/세션 `4d9f285`, 클래식 복원 `1ffec3a`)을
점검했다. 코드 자체는 멀쩡했다(pytest 920·ruff·실제 브라우저 39패널 순회 오류 0). 꼬여 있던 것은
세 가지였고 전부 정리했다.

- **영어/한국어 혼용 UI** — Codex 가 만든 알림 큐·계정 권한·탐지 품질·증거 요약·조사 drawer·
  코파일럿·출처 배너·지도 안내를 한국어로 통일(템플릿 10·JS 14·Python 5·테스트 4 파일).
  출처 배지(REAL/DEMO/SIMULATED…)·상태 토큰(OPEN/ACK)·API 값·고유명사는 그대로다.
- **문서 잔재** — 루트 `HANDOFF.md`(07-20 스냅샷), `docs/IDENTITY_ASSET.md` 와 표시되지 않는
  로그인 생성 이미지(`static/identity/`), `CLAUDE.md` 의 `app.py` 중복 행 제거.
- **운영 서버 사망** — 09-09 22:36 부터 죽어 있었다(WSL 재시작 포함). systemd 사용자 서비스로
  전환(2절). 이제 죽어도 5초 뒤 되살아난다.

## 기존 디자인 복원 · 최신 단계 (2026-09-09)

사용자 요청으로 TRACE 이전 한국어 메뉴·검정/청록색 테마·관제 센터·로그인을 복원했다.
39개 패널과 조사/권한/세션/감사 개선은 유지하며, 추가 집계는 하단 저장 증거 요약으로 이동했다.
세부 변경과 서버 갱신 절차: [CLASSIC_RESTORE](CLASSIC_RESTORE.md).
포트 5055의 오래된 프로세스를 실제 갱신했고, 인증된 요약 API 200·Socket.IO 연결·
syslog 5514 리스너와 대응 정책 불변을 확인했다. 현재는 systemd 서비스가 기준이다(2절).
기존 단일 관리자 메모리 세션은 다시 로그인해야 한다. 아래 이전 단계의 “운영 프로세스 변경 없음”은 당시 기록이다.

## 역할 경계·부하 검증 인계 · 2026-09-09

Access & roles가 추가되어 현재 총 39개 워크스페이스다. 로컬 4역할, 서버 세션 회수,
계정 감사와 동시 집계 개선을 구현했다. 기존 단일 관리자 설정은 그대로 동작하고
다중 사용자는 `AUTH_USERS_DB`로 명시적으로 활성화한다. SSO/MFA는 미구현이다.

- 적용/복구/권한 범위: [ACCESS_CONTROL](ACCESS_CONTROL.md)
- 사본 부하 시험과 실제 측정: [LOAD_VALIDATION](LOAD_VALIDATION.md)
- 기존 .env·운영 프로세스·보호 서버 변경 없음. 커밋/푸시는 배포 완료가 아니다.
- 다음 우선순위: IdP 선정 후 SSO/MFA, 영속 이벤트/전이 시각, 수집기별 출처,
  배포 환경에서의 장시간 부하·복구 검증.

## TRACE 콘솔 변경 인계 · 이전 단계 (2026-09-09)

기존 Flask 앱의 셸/조사 흐름을 TRACE로 개선했다. 기존 37개 기능은 유지하고
Detection Quality를 추가해 총 38개 워크스페이스가 됐다. 운영 프로세스나 보호 서버,
방화벽, 패치, `.env`, 운영 DB는 이 작업에서 변경하지 않았다.

- 구현과 전체 검증 결과: [CONSOLE_REDESIGN](CONSOLE_REDESIGN.md)
- API/출처/버퍼/조회 범위/제약: [TRACE_CONSOLE](TRACE_CONSOLE.md)
- 다음 우선순위: 인증·역할 경계, 수집기별 출처 기록, 영속 이벤트/전이 시각, 부하 검증.

아래 표와 운영 환경 수치는 **TRACE 변경 이전의 인계 스냅샷**이며 이번 작업에서
운영 상태를 재확인하거나 배포 완료를 주장하는 자료가 아니다.

## 1. 이전 운영 스냅샷

| 항목 | 상태 |
|---|---|
| 코드 | `main` 최신, 원격과 동기화. 마지막 큰 변경: Zeek 연동(09-09), 허니팟 제거(09-08) |
| 검증 | pytest 857건 + 실서버 통합 + 브라우저 순회(Playwright 37패널) + Docker 빌드. CI 가 매 push 전부 돈다 |
| 운영 서버 | WSL2 홈서버, 포트 **5055**, systemd 사용자 서비스 `soc-dashboard`(09-11~). Tailscale 로만 외부 접근(`http://100.64.140.27:5055`) |
| 센서 | 패킷 실캡처 eth0(약 300~400 pps) · SSH auth.log(실제) · KR/USA 매매 서버 syslog · Snort · EDR(psutil) · NetMon · YARA. **Suricata·Zeek 는 미설치 → waiting** |
| ML | Isolation Forest **실트래픽 모델**(09-08 15:23, 3,109건). 24시간마다 자동 갱신. 판정은 참고용(advisory) — 탐지·차단 경로 미연결 |
| 라벨 | 그룹 128건 → 실측 알림 459건 전부 덮음. **개별 라벨 0건** → precision/recall 아직 측정 불가 |
| 보안 헤더 | CSP `script-src 'self'`(인라인 핸들러 0개). 인증·CSRF·보안 헤더 전부 적용 |

## 2. 운영 방법

**2026-09-11 부터 systemd 사용자 서비스**(`scripts/soc-dashboard.service`)로 돈다.
WSL 재시작·OOM 킬 뒤에도 자동 복구된다(`Restart=always`, linger 활성).
`logs/dashboard.pid` 는 서비스가 기동할 때마다 같이 갱신되므로 기존 확인 절차도 그대로 쓸 수 있다.

```bash
systemctl --user status soc-dashboard     # 살아 있나 (Main PID · 메모리)
systemctl --user restart soc-dashboard    # 재기동 (템플릿·파이썬 변경 반영. 사용자 로그아웃됨. CSS/JS 는 디스크에서 바로 제공)
journalctl --user -u soc-dashboard -n 50  # 서비스 자체 이벤트 (앱 로그는 logs/dashboard.out)
# 유닛 파일을 바꿨으면
cp scripts/soc-dashboard.service ~/.config/systemd/user/ && systemctl --user daemon-reload && systemctl --user restart soc-dashboard
```

- 수동으로 띄우지 말 것 — 서비스가 5초 뒤 다시 띄워 포트가 충돌한다. 잠시 내리려면 `systemctl --user stop soc-dashboard`.
- `.env` 는 실차단 모드(`SOAR_BLOCK_MODE=ufw`, `SOAR_AUTO_BLOCK=True`)다. 실험·부하 시험은 **반드시** 격리 디렉터리에서 `SOAR_BLOCK_MODE=simulate` 로 띄울 것.
- 데모로 어디서나: `docker compose up --build` (센서 없이 전체 화면, 차단은 simulate 강제).

## 3. 알려진 문제 · 결정 대기

1. **서버가 조용히 죽던 문제 — 09-11 해결.** 09-08 과 09-09 두 번(두 번째는 09-09 22:36 ~ 09-11, WSL 재시작 포함) 죽어 있었다. systemd 사용자 서비스로 전환해 자동 재시작된다(2절). 근본 원인(OOM 의심, WSL 메모리 9.7GB 중 가용 4GB)은 그대로이므로 메모리 추이는 `systemctl --user status` 로 가끔 볼 것.
2. **개별 라벨 6건 판정 대기** — YARA 테스트 파일 3(8/29, 이 저장소 검증용 스크래치 파일 → 오탐 권고), `/tmp/plab-sbx-*` 실행 3(사용자 실습 도구로 보임 → 오탐 권고). `plab-sbx` 가 무엇인지 사용자 확인 필요. 확인되면 EDR 예외 접두(`EDR_TMPEXEC_ALLOW_PREFIXES`)에 `/tmp/plab-sbx-` 추가 여부도 결정.
3. **개별 라벨 100건**은 앞으로 쌓이는 실측 알림(최근 이틀 32건 속도)에서 알림 화면의 "정탐/오탐 확정"으로 채운다. 그룹 판정을 건별로 복사하지 말 것 — 같은 근거를 100번 복사한 것은 정직한 라벨이 아니다.
4. **허니팟은 제거됨**(사용자 결정, 09-08. **재구현 계획 없음** — 09-11 확정). 전체 구현은 git `d75da7c` 이전에 있다. 알림 유형 `HONEYPOT`·플레이북 `PB-HONEYPOT-BLOCK` 정의는 과거 알림 표시를 위해 남아 있다.
5. Suricata·Zeek 는 코드만 있고 로컬 미설치. 설치법은 [integrations.md](integrations.md).

## 4. 최근 2일 변경 요약 (커밋 순)

| 날짜 | 내용 |
|---|---|
| 09-06 | UI/UX 감사 20/20 마감(패널 지연 실체화, DOM 2,906→467 요소), 모바일 표 넘침, 문서 동기화 |
| 09-07 | 전체 점검 결함 3건, 브라우저 순회 테스트화, 인라인 핸들러 152개 제거 → CSP `'self'`, Suricata 연동, iOS 아이콘, Dockerfile, 허니팟 노출 스크립트(이후 제거) |
| 09-08 | WSL 재시작 후 실캡처 개통(인터페이스 자동 선택 버그), ML 실트래픽 재학습 + 자동 재학습(15:23 첫 실행), vulners 내장, 사이드바 아코디언, SOAR 패널 정리, 리포트 모바일·재기동 생성 수정, 허니팟 제거, IDS 분류→MITRE, EDR `nc`/pytest 오탐 근원 수정, 라벨링 1차 |
| 09-09 | Zeek 연동, 평가 스크립트 건별 라벨 집계, runc 그룹 라벨, 서버 사망 발견·복구 |

## 5. 다음 할 일 (우선순위)

1. 개별 라벨 6건 판정 + `plab-sbx` 확인.
2. 개별 라벨 100건 도달 후 `python scripts/eval_ml.py` 로 precision/recall 첫 측정 → ML 을 탐지 경로에 연결할지 결정(docs/ml_models.md 5절).
3. Suricata·Zeek 실제 설치 — `sudo bash scripts/install_ids.sh` 한 번(09-11 준비, sudo 라 사용자 실행).
5. TRACE 문서의 다음 우선순위(IdP 선정 후 SSO/MFA, 영속 이벤트/전이 시각, 수집기별 출처).

## 6. 확인 명령 모음

```bash
./venv/bin/python scripts/eval_ml.py            # 데이터·라벨·운영 모델 현황 (숫자를 만들지 않는다)
./venv/bin/python -m pytest -m "not browser"    # 빠른 전체 (약 70초)
./venv/bin/python -m pytest tests/test_browser_sweep.py   # 실제 브라우저 37패널 (약 75초)
grep -n "자동 재학습\|실트래픽 모델" logs/dashboard.out    # ML 갱신 기록
cat data/models/iso_forest_real.json             # 운영 ML 모델 메타데이터
```
