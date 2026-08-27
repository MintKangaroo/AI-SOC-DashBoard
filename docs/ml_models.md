# 자체 ML 모델

> **요약**: 운영 모델은 **Isolation Forest 1종**입니다. 나머지 3종(Random Forest ·
> LSTM Autoencoder · Q-Learning)은 실데이터로 학습·검증된 적이 없고 출력이 어떤
> 판단 경로에도 연결되어 있지 않아 `experimental/` 로 격리했습니다.
> **현재 성능 수치를 제시하지 않습니다.** 측정에 필요한 데이터가 없기 때문이며,
> 그 부족분은 아래에 숫자로 적었습니다.

최종 갱신: 2026-08-27

---

## 1. 현재 상태

| 모델 | 상태 | 학습 데이터 | 판단 경로 연결 |
|---|---|---|---|
| Isolation Forest | **운영** | 합성 200샘플 (부트스트랩) | ❌ 참고용(advisory only) |
| Random Forest | 격리 (`experimental/`) | 합성 1,200샘플 | ❌ |
| LSTM Autoencoder | 격리 (`experimental/`) | 합성 400시퀀스 · TF 미설치로 미실행 | ❌ |
| Q-Learning | 격리 (`experimental/`) | 온라인(닫힌 루프) | ❌ |

격리 사유와 복귀 조건은 [`experimental/README.md`](../experimental/README.md).

### Isolation Forest (운영)

- **종류**: 비지도 이상탐지 (scikit-learn)
- **하이퍼파라미터**: `n_estimators=200`, `contamination=0.08`, `random_state=42`
- **입력**: 트래픽 피처 8개 (아래 2장)
- **주기**: 3초
- **출력**: `score_samples` 이상 점수 + 이상 여부 boolean
- **저장 위치**: `data/models/iso_forest.pkl`, `data/models/scaler.pkl`

**왜 이것만 남겼나**: 비지도 학습이라 **라벨 없이 실트래픽으로 재학습할 수 있는
유일한 모델**이기 때문입니다. 지금 이 모델도 합성 데이터로 학습된 상태이므로
현재 출력은 정상 프로파일 근사치 이상의 의미가 없습니다.

---

## 2. 입력 피처

`FEATURE_NAMES` (8개, `modules/ml_analyst.py`):

| # | 피처 | 설명 | 출처 |
|---|---|---|---|
| 0 | `pps` | 초당 패킷 수 | `packet_analyzer.get_stats()` |
| 1 | `bps` | 초당 바이트 수 | 〃 |
| 2 | `tcp_ratio` | TCP 비율 | 〃 (전체 패킷 대비) |
| 3 | `udp_ratio` | UDP 비율 | 〃 |
| 4 | `icmp_ratio` | ICMP 비율 | 〃 |
| 5 | `unique_src` | 고유 출발지 IP 수 | 최근 패킷 윈도우 |
| 6 | `unique_dst_port` | 고유 목적지 포트 수 | 〃 |
| 7 | `avg_pkt_size` | 평균 패킷 크기 | 총 바이트 / 총 패킷 |

이 순서는 `modules/ml_feature_store.py` 의 `FEATURE_COLUMNS` 와 일치해야 하며,
`tests/test_ml_analyst.py::test_feature_columns_match_analyst_feature_names` 가
검증합니다. 어긋나면 재학습 데이터가 조용히 망가집니다.

---

## 3. 데이터 파이프라인

```
packet_analyzer.get_stats()
  → ml_analyst.feed_traffic()        (3초 주기, wiring.py)
      ├→ _feature_buffer (deque 60)  → 실시간 분석
      └→ ml_feature_store.record()   → data/ml_features.db (append-only)
                                        origin: real | demo 구분 저장
  → _run_models() → Isolation Forest
  → SocketIO emit("ml_analysis")     → ML 패널
```

### 트래픽 피처 저장소 (`data/ml_features.db`)

2026-08-27 신설. 그 이전에는 **피처가 메모리에만 존재했습니다**
(`deque(maxlen=60)` = 최대 3분 분량). 파일이나 DB로 저장하는 코드가 없었습니다.

이것이 왜 중요한가: 모든 라벨은 `alerts` 테이블(알림 단위)에 있는데, 모델의 입력은
트래픽 피처입니다. **즉 모델의 입력 공간에는 라벨은커녕 데이터 자체가 한 건도
기록된 적이 없었고**, 그 상태에서는 실트래픽 재학습도 홀드아웃 평가도 룰 베이스라인
비교도 구조적으로 불가능했습니다.

- append-only SQLite (WAL + `busy_timeout=10000`)
- 배치 커밋 (20건 또는 60초) — 3초 주기 fsync 부담 완화
- `origin` 컬럼으로 `real` / `demo` 구분 → 재학습 시 demo 제외 가능
- 보존: `ML_FEATURE_RETENTION_DAYS` (기본 180일, 알림 90일보다 길게)

---

## 4. 성능 — 현재 측정 불가

**정직하게 적습니다: 지금 제시할 수 있는 성능 수치가 없습니다.**

`scripts/eval_ml.py` 를 실행하면 매번 현재 상태를 재계산합니다.
2026-08-27 기준 출력:

```
트래픽 피처 (data/ml_features.db)
  전체 0건 · 실트래픽 0건 · 데모 0건

라벨 (사람이 확정한 판정만 집계)
  활성 alerts.db : 사람 1건 (정탐 1 / 오탐 0) · 자동 6건 · 전체 알림 100건
  아카이브       : 사람 0건 · 전체 알림 110,748건

판정
  IF 실트래픽 재학습 : 불가 — 3,000건 부족 (약 2.5시간 가동분)
  precision/recall   : 불가 — 사람 라벨 99건 부족
```

### 측정에 필요한 데이터

| 목표 | 필요량 | 현재 | 부족 |
|---|---|---|---|
| IF 실트래픽 재학습 | 실트래픽 피처 3,000건 | 0 | 3,000건 (≈ 2.5시간 연속 가동) |
| precision / recall / F1 | 사람 확정 라벨 100건 | 1 | 99건 |
| Random Forest 복귀 | 클래스당 30건 (총 180건+) | 1 | 179건+ |

### 룰 베이스라인이 기준선입니다

ML 성능은 **"ML 없이 임계값 규칙만 썼을 때"** 와 비교해야 의미가 있습니다.
`scripts/eval_ml.py::rule_baseline` 이 그 기준선을 구현하고 있으며, 실데이터가
쌓이면 자동으로 비교합니다. **ML 이 베이스라인보다 못하면 그 사실을 이 문서에
그대로 적습니다.**

### 합성 데이터 대조군 — 성능 주장의 근거가 아님

참고로, 기존 합성 데이터에서 홀드아웃(7:3 stratified) 평가를 하면:

| 모델 | F1 (macro) | 정확도 |
|---|---|---|
| 룰 베이스라인 (손으로 쓴 if문 6줄) | **0.9972** | 0.9972 |
| Random Forest | **1.0000** | 1.0000 |

**이 수치를 성능으로 인용하면 안 됩니다.** 합성 데이터는 클래스별로 서로 겹치지 않는
uniform 구간에서 난수를 뽑아 만들었습니다(예: NORMAL은 `pps ∈ [10,300]`, DDoS는
`pps ∈ [5000,50000]`). 문제가 상자 6개로 분리되어 있으니 트리 앙상블이 만점을 받는
것은 당연하고, **손으로 쓴 규칙 6줄이 0.997을 받는 것이 그 증거입니다.**
여기서 측정되는 것은 모델 품질이 아니라 데이터 생성기의 분리도입니다.

이 사실은 `tests/test_ml_analyst.py::test_synthetic_classes_are_trivially_separable_by_rules`
로 회귀 고정해 두었습니다. 성능 주장을 되살리려는 시도에 대한 방어선입니다.

---

## 5. 라벨 신뢰성과 편향 — 반드시 읽을 것

이 절은 위 지표를 해석할 때의 전제 조건입니다. 지표가 좋아 보이게 쓰지 않았습니다.

### 5.1 라벨 생산자가 셋이고, 다수가 사람이 아닙니다

| 생산자 | 코드 | 성격 | 신뢰도 |
|---|---|---|---|
| 분석가 버튼 | `04-ml-mitre.js` → `/api/ml/feedback` | 사람 판단 | 높음 |
| 알림 확정 판정 | `/api/alerts/<id>/verdict` → `alerts.verdict` | 사람 판단 (근거 3자 이상 강제) | 높음 |
| **AI 자기 판정** | `ai_analyst.py::_feedback_to_ml` | Claude 의 `is_true_positive` 자동 반영 | **낮음** |
| **SOAR 규칙 판정** | `soar.py` (정탐/오탐 분기) | 규칙 또는 AI 결과 자동 반영 | **낮음** |

**핵심 문제**: AI 판정을 ML 학습 라벨로 쓰고, 그 ML 이 다시 AI 판단의 참고가 되면
**상호 강화 루프**가 됩니다. 두 시스템이 함께 틀려도 서로를 확증하며 지표는 좋아집니다.

이 때문에 `scripts/eval_ml.py` 는 `verdict_actor` 가 `SYSTEM` 인 라벨을
**사람 라벨 집계에서 제외**합니다. 위 "사람 1건 / 자동 6건" 구분이 그것입니다.

### 5.2 라벨과 모델 입력의 공간이 다릅니다

- 모델 입력: 3초 주기 트래픽 피처 8개 (집계 수치)
- 라벨 위치: `alerts` 테이블 (개별 알림 이벤트)

둘을 잇는 유일한 방법은 **시각 기준 조인**이며, 이는 약한 라벨링(weak labeling)입니다.
"이 3초 구간에 알림이 있었다 → 이 피처 벡터는 이상이다"라는 가정에는 다음 오차가 따릅니다.

- 알림이 트래픽 이상 없이 발생할 수 있습니다 (허니팟 접촉, Sigma 프로세스 매치 등은
  네트워크 집계 피처에 흔적을 남기지 않습니다). → **거짓 양성 라벨**
- 트래픽 이상이 알림 없이 발생할 수 있습니다 (탐지 규칙이 없는 공격). → **거짓 음성 라벨**
- 3초 경계에서 알림 시각과 피처 시각이 어긋납니다. → **경계 오차**

조인 방식은 데이터가 실제로 쌓인 뒤 확정합니다 (현재 조인 대상 0건).
확정 시 이 절에 그 설계와 예상 오차를 함께 적습니다.

### 5.3 선택 편향

분석가는 **눈에 띄는 알림**을 우선 판정합니다. CRITICAL 은 판정되고 LOW 는 방치되는
경향이 있으므로, 사람 라벨 집합은 심각도 분포가 실제 알림 분포와 다릅니다.
현재 활성 알림 100건 중 CRITICAL 8 / HIGH 92 인데 사람 판정은 1건뿐이라
이 편향의 크기는 **아직 측정조차 불가능합니다.**

### 5.4 클래스 불균형

아카이브 110,748건의 위협 유형 분포는 HONEYPOT 35,963 / SIGMA_MATCH 14,193 /
EDR_THREAT 14,116 / BRUTE_FORCE 11,661 … 로 상위 유형에 크게 쏠려 있습니다.
라벨이 이 분포를 따르면 소수 유형의 recall 은 신뢰구간이 매우 넓어집니다.
평가 시 유형별로 나눠 보고해야 하며, 전체 F1 하나로 요약하면 오해를 부릅니다.

### 5.5 이 문서가 지키는 규칙

1. 성능 주장은 `scripts/eval_ml.py` 가 출력한 숫자로만 합니다.
2. 합성 데이터 수치는 반드시 대조군임을 명시해 인용합니다.
3. 사람 라벨과 자동 라벨을 분리해 집계합니다.
4. ML 이 룰 베이스라인보다 못하면 그대로 적습니다.
5. 측정할 수 없으면 "측정 불가"라고 적습니다. 추정치를 쓰지 않습니다.

---

## 6. API 엔드포인트

| 엔드포인트 | 설명 |
|---|---|
| `GET /api/ml/status` | 모델 상태 + 피처 수집 현황 + 누적 라벨 수 |
| `POST /api/ml/analyze` | 수동 분석 트리거 |
| `GET /api/ml/log?limit=20` | 분석 로그 |
| `POST /api/ml/feedback` | `{is_false_positive: bool}` 피드백 |

`GET /api/ml/status` 의 `rl` 필드는 `{"enabled": false, "reason": "experimental"}`
를 반환합니다. Q-Learning 이 격리됐으므로 활성인 척하지 않습니다.

---

## 7. 데모 fallback

scikit-learn 이 없으면 `MLAnalyst` 초기화가 실패하고 `model_status` 에 오류가
기록되지만, **대시보드의 나머지 기능은 정상 동작합니다.** ML 판정은 어떤 탐지·차단
경로에도 연결되어 있지 않기 때문입니다(`summary.advisory_only = true`).

`demo=True` 로 시작하면 수집되는 피처의 `origin` 이 `demo` 로 기록되어
실트래픽 재학습 대상에서 자동 제외됩니다.

---

## 8. 변경 이력

**2026-08-27** — ML 스택 정리 (`chore/ml-stack-triage`)

- Random Forest · LSTM Autoencoder · Q-Learning 을 `experimental/` 로 격리
- `MLFeatureStore` 신설 — 트래픽 피처 영속화 (재학습·평가의 전제)
- `scripts/eval_ml.py` 신설 — 데이터 부족 시 숫자를 만들지 않는 평가 스크립트
- 테스트 26건 신설 (이전 0건)
- LSTM 학습이 IF/RF 의 스케일러를 덮어쓰던 버그 제거

**이 문서의 이전 버전에 있던 사실 오류** (모두 코드와 대조해 정정):

| 이전 기술 | 실제 |
|---|---|
| "시드 데이터(합성) 1000개 × 6클래스" | 200개 × 6클래스 = 1,200건 |
| `isolation_forest.pkl` / `random_forest.pkl` | `iso_forest.pkl` / `rf_classifier.pkl` |
| `q_table.pkl` 저장 | **생성된 적 없음** — Q-테이블 저장 코드 자체가 부재 |
| 보상 "정탐 +5 / 오탐 -3 / 과다알림 -10" | 실제 `+5 / +2 / +1 / -2`, 외부 정답 미사용 |
| 상태 3축 = "오탐율 × 알림량 × **현재 임계값**" | 3번째 축은 **pps(트래픽 수준)** |

또한 `CLAUDE.md` 가 문서화했던
`사용자 피드백(FP 버튼) → Q-Learning 보상 → 임계값 자동 튜닝` 흐름은
**코드에 존재한 적이 없습니다.** FP 피드백은 상태 계산에만 쓰이고 보상 함수
(`_compute_reward`)에는 닿지 않았습니다.
