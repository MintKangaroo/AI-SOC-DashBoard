# experimental/ — 실험적 코드 격리 구역

**여기 있는 코드는 제품 코드가 아닙니다.** 대시보드 실행 경로에서 import 되지 않으며,
전부 삭제해도 대시보드는 정상 동작합니다.

## 왜 격리했나

`modules/ml_analyst.py` 에는 Isolation Forest · Random Forest · LSTM Autoencoder ·
Q-Learning 4종이 있었습니다. 2026-08-27 코드 감사에서 다음이 확인되어 3종을 분리했습니다.

**공통 사항 — 네 모델 전부 실데이터를 학습한 적이 없습니다.** 학습 데이터는
`numpy.random.RandomState(42)` 로 생성한 합성 데이터이며(클래스당 200샘플 × 6클래스),
클래스별 구간이 서로 겹치지 않는 uniform 상자입니다. 이 데이터셋에서는 손으로 쓴
if문 6줄이 macro-F1 **0.997**, Random Forest 가 **1.000** 을 받습니다.
**측정되는 것은 모델 품질이 아니라 데이터 생성기의 분리도입니다.**

**공통 사항 2 — 네 모델의 출력 중 어느 것도 탐지·차단 판단에 쓰이지 않았습니다.**
`soar.py` 는 `self.ml` 을 보관하지만 `mark_alert()` 호출(쓰기)에만 씁니다.
`threat_detector.py` 에는 ML 참조가 없습니다. 데이터 흐름은 단방향이며 ML 출력의
종착지는 SocketIO → ML 패널 차트였습니다.

## 격리된 모듈

| 파일 | 원래 역할 | 격리 사유 (요약) | 복귀 조건 |
|---|---|---|---|
| `rf_classifier.py` | 6클래스 위협 분류 | 사람 판정 라벨 **1건**. 지도학습 검증 불가. OOD 입력에서 confidence≥80 을 그대로 출력해 필터가 무력 | 클래스당 실제 라벨 30건+ (총 180건+) 확보 후 `scripts/eval_ml.py` 가 룰 베이스라인 대비 우위를 보일 것 |
| `lstm_autoencoder.py` | 시계열 재구성 오차 | 학습 시퀀스 400개의 각 타임스텝이 **i.i.d. 난수** — 학습할 시간 의존성이 데이터에 없음. 샘플 수를 늘려도 해소 안 됨. 게다가 TensorFlow 미설치로 실행 자체가 안 됨 | 실트래픽 연속 구간 확보 + TF 를 정식 의존성으로 승격할 근거 |
| `threshold_qlearner.py` | 탐지 임계값 자동 튜닝 | 보상이 **모델 자신의 출력**만 봄(닫힌 루프). Q-테이블 미영속 — 재시작마다 리셋. `threshold_multiplier` 가 어떤 탐지 임계값에도 미적용 | 분석가 확정 판정 기반 보상 + Q-테이블 영속화 + 실제 임계값 연결, 셋 다 |
| `synthetic_data.py` | 합성 데이터 생성기 | 위 3종의 학습 데이터 소스. 회귀 테스트·형태 검증용으로만 유지 | — |

## 제거된 버그

`lstm_autoencoder.py` 의 원본(`_train_lstm_autoencoder`)은 `self.scaler.fit(flat)` 로
**Isolation Forest 와 Random Forest 가 학습에 사용한 스케일러를 덮어썼습니다.**
주석은 "이미 fit 됐지만 재확인"이었으나 `StandardScaler.fit` 은 mean/std 를 교체합니다.
캐시가 없는 최초 실행이나 `.keras` 로드 실패 시 IF/RF 의 입력 분포가 조용히
어긋났습니다. 이 모듈을 분리하면서 해당 버그가 함께 제거됐습니다.

## 문서와 코드의 불일치 (정정 완료)

격리 과정에서 `docs/ml_models.md` 의 사실 오류 5건을 확인했습니다.

- 학습 샘플 "1000개 × 6클래스" → 실제 **200개 × 6클래스**
- 모델 파일명 3개 오기 (`isolation_forest.pkl` → `iso_forest.pkl` 등)
- `data/models/q_table.pkl` — **생성된 적이 없음** (Q-테이블 저장 코드 부재)
- 보상값 "+5 / -3 / -10" → 실제 `+5 / +2 / +1 / -2`, 그나마 외부 정답 미사용
- 상태 3번째 축 "현재 임계값" → 실제 **pps(트래픽 수준)**

또한 `CLAUDE.md` 가 문서화했던
`사용자 피드백(FP 버튼) → Q-Learning 보상 → 임계값 자동 튜닝` 흐름은
**코드에 존재한 적이 없습니다.** FP 피드백은 상태 계산에만 쓰이고 보상에는
닿지 않았습니다.

## 의존 규칙

- `modules/`, `api/`, `app.py`, `wiring.py` 는 `experimental/` 을 **import 하지 않습니다.**
- 반대 방향(`experimental/` → `modules/`)도 두지 않습니다. 실험 코드가 제품 코드의
  스케일러나 상태를 건드리지 못하게 하기 위해서입니다.
- 이 규칙은 `tests/test_ml_analyst.py` 에서 검증합니다.
