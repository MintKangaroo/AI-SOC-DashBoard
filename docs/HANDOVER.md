# 인수인계 — 2026-09-09 기준

이 문서는 "지금 어디까지 됐고, 무엇이 돌아가고 있고, 무엇을 결정해야 하는가"만 적는다.
설계·근거는 [README](../README.md)·[architecture](architecture.md)·[CLAUDE.md](../CLAUDE.md)에 있다.

## 1. 지금 상태 한 눈에

| 항목 | 상태 |
|---|---|
| 코드 | `main` 최신, 원격과 동기화. 마지막 큰 변경: Zeek 연동(09-09), 허니팟 제거(09-08) |
| 검증 | pytest 857건 + 실서버 통합 + 브라우저 순회(Playwright 37패널) + Docker 빌드. CI 가 매 push 전부 돈다 |
| 운영 서버 | WSL2 홈서버, 포트 **5055**, `logs/dashboard.pid` 로 PID 관리. Tailscale 로만 외부 접근(`http://100.64.140.27:5055`) |
| 센서 | 패킷 실캡처 eth0(약 300~400 pps) · SSH auth.log(실제) · KR/USA 매매 서버 syslog · Snort · EDR(psutil) · NetMon · YARA. **Suricata·Zeek 는 미설치 → waiting** |
| ML | Isolation Forest **실트래픽 모델**(09-08 15:23, 3,109건). 24시간마다 자동 갱신. 판정은 참고용(advisory) — 탐지·차단 경로 미연결 |
| 라벨 | 그룹 128건 → 실측 알림 459건 전부 덮음. **개별 라벨 0건** → precision/recall 아직 측정 불가 |
| 보안 헤더 | CSP `script-src 'self'`(인라인 핸들러 0개). 인증·CSRF·보안 헤더 전부 적용 |

## 2. 운영 방법

```bash
# 기동 (setsid 로 셸에서 분리, PID 기록)
setsid ./venv/bin/python app.py > logs/dashboard.out 2>&1 < /dev/null &
ss -ltnp | grep ':5055 ' | grep -oP 'pid=\K[0-9]+' | head -1 > logs/dashboard.pid

# 재기동 (템플릿·파이썬 변경은 재기동해야 반영. CSS/JS 는 디스크에서 바로 제공)
kill $(cat logs/dashboard.pid)   # 그 뒤 위 기동 명령

# 살아 있나
kill -0 $(cat logs/dashboard.pid) && echo up
```

- `.env` 는 실차단 모드(`SOAR_BLOCK_MODE=ufw`, `SOAR_AUTO_BLOCK=True`)다. 실험·부하 시험은 **반드시** 격리 디렉터리에서 `SOAR_BLOCK_MODE=simulate` 로 띄울 것.
- **WSL 재시작 뒤엔 서버가 죽어 있다.** pidfile 의 PID 가 없으면 그 상태다.
- 데모로 어디서나: `docker compose up --build` (센서 없이 전체 화면, 차단은 simulate 강제).

## 3. 알려진 문제 · 결정 대기

1. **서버가 조용히 죽는다.** 09-08 22:35 ~ 09-09 18:31 사이 로그 없이 죽어 있었다. 커널 로그에 OOM 킬(다른 python 5.4GB) 기록이 있고 WSL 메모리 9.7GB 중 가용 4GB. 자동 재시작이 없다.
   → **권고**: systemd 사용자 서비스(`Restart=always`)로 전환. 미구현.
2. **개별 라벨 6건 판정 대기** — YARA 테스트 파일 3(8/29, 이 저장소 검증용 스크래치 파일 → 오탐 권고), `/tmp/plab-sbx-*` 실행 3(사용자 실습 도구로 보임 → 오탐 권고). `plab-sbx` 가 무엇인지 사용자 확인 필요. 확인되면 EDR 예외 접두(`EDR_TMPEXEC_ALLOW_PREFIXES`)에 `/tmp/plab-sbx-` 추가 여부도 결정.
3. **개별 라벨 100건**은 앞으로 쌓이는 실측 알림(최근 이틀 32건 속도)에서 알림 화면의 "정탐/오탐 확정"으로 채운다. 그룹 판정을 건별로 복사하지 말 것 — 같은 근거를 100번 복사한 것은 정직한 라벨이 아니다.
4. **허니팟은 제거됨**(사용자 결정, 09-08). 전체 구현은 git `d75da7c` 이전에 있다. 알림 유형 `HONEYPOT`·플레이북 `PB-HONEYPOT-BLOCK` 정의는 과거 알림 표시를 위해 남아 있다.
5. Suricata·Zeek 는 코드만 있고 로컬 미설치. 설치법은 [integrations.md](integrations.md).

## 4. 최근 2일 변경 요약 (커밋 순)

| 날짜 | 내용 |
|---|---|
| 09-06 | UI/UX 감사 20/20 마감(패널 지연 실체화, DOM 2,906→467 요소), 모바일 표 넘침, 문서 동기화 |
| 09-07 | 전체 점검 결함 3건, 브라우저 순회 테스트화, 인라인 핸들러 152개 제거 → CSP `'self'`, Suricata 연동, iOS 아이콘, Dockerfile, 허니팟 노출 스크립트(이후 제거) |
| 09-08 | WSL 재시작 후 실캡처 개통(인터페이스 자동 선택 버그), ML 실트래픽 재학습 + 자동 재학습(15:23 첫 실행), vulners 내장, 사이드바 아코디언, SOAR 패널 정리, 리포트 모바일·재기동 생성 수정, 허니팟 제거, IDS 분류→MITRE, EDR `nc`/pytest 오탐 근원 수정, 라벨링 1차 |
| 09-09 | Zeek 연동, 평가 스크립트 건별 라벨 집계, runc 그룹 라벨, 서버 사망 발견·복구 |

## 5. 다음 할 일 (우선순위)

1. systemd 사용자 서비스로 자동 재시작 — 서버가 죽으면 피처·알림 수집이 멈추고 ML 갱신도 멈춘다.
2. 개별 라벨 6건 판정 + `plab-sbx` 확인.
3. 개별 라벨 100건 도달 후 `python scripts/eval_ml.py` 로 precision/recall 첫 측정 → ML 을 탐지 경로에 연결할지 결정(docs/ml_models.md 5절).
4. Suricata·Zeek 실제 설치(선택).
5. 허니팟 재구현(사용자가 원할 때).

## 6. 확인 명령 모음

```bash
./venv/bin/python scripts/eval_ml.py            # 데이터·라벨·운영 모델 현황 (숫자를 만들지 않는다)
./venv/bin/python -m pytest -m "not browser"    # 빠른 전체 (약 70초)
./venv/bin/python -m pytest tests/test_browser_sweep.py   # 실제 브라우저 37패널 (약 75초)
grep -n "자동 재학습\|실트래픽 모델" logs/dashboard.out    # ML 갱신 기록
cat data/models/iso_forest_real.json             # 운영 ML 모델 메타데이터
```
