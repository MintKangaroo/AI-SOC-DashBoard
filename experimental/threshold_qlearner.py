"""Q-Learning 임계값 튜너 (실험적 — 비활성).

`modules/ml_analyst.py` 에서 이관.

## 격리 사유

1. **보상에 외부 정답 신호가 없다.** 원본 `_compute_reward(result, action)` 는
   `result["summary"]["threats"]` — 즉 **자신이 튜닝하는 모델들의 출력** 만 본다.
   분석가 FP 피드백(`mark_alert`)이 채우는 창은 `_state_index` 의 **상태** 계산에만
   쓰이고 보상에는 닿지 않는다. 결과적으로 "자기가 조정하는 대상과 얼마나
   일치하는가"로 보상받는 닫힌 루프였다.
   → `CLAUDE.md` 가 문서화했던 `FP 버튼 → Q-Learning 보상 → 임계값 자동 튜닝`
     흐름은 코드에 존재한 적이 없다.
2. **학습이 누적되지 않는다.** `q_table` 은 `__init__` 에서 `np.zeros` 로 만들어지고
   저장·복원 코드가 없다. 프로세스를 재시작할 때마다 0으로 리셋된다.
   `docs/ml_models.md` 가 명시했던 `data/models/q_table.pkl` 은 생성된 적이 없다.
3. **출력이 어디에도 적용되지 않았다.** `threshold_multiplier` 의 유일한 소비
   지점이 LSTM 분기 내부였고, tensorflow 미설치로 그 분기가 실행되지 않았다.
   따라서 이 에이전트의 출력은 UI 차트의 숫자 외에 **어떤 탐지 임계값에도
   반영되지 않았다.** `threat_detector` 의 DDoS·포트스캔 임계값과는 무관하다.
4. **상태공간 대비 수렴 가능성.** 27상태 × 3행동 = Q값 81개. 확률적 보상 하에서
   (s,a)쌍당 수백 회 방문이 필요하므로 최소 ~8,100 스텝(3초 주기 = 7시간 연속
   가동)이 필요하다. 그런데 트래픽 구간이 `min(int(pps/500), 2)` 라 홈서버
   1대 트래픽에서는 `t=0` 에 고정되어 실질 방문 상태가 6개 이하다.
   재시작 리셋(2번)과 겹치면 수렴은 구조적으로 불가능하다.

## 복귀 조건

(a) 보상이 분석가 확정 판정(`alerts.verdict`, `verdict_actor`=사람)에서 오고,
(b) Q-테이블이 영속화되며,
(c) `threshold_multiplier` 가 실제 탐지 임계값에 연결될 것.
셋 다 충족되어야 의미가 있다. 그 전에는 고정 임계값이 더 정직하다.
"""
import random
from collections import deque

import numpy as np


class ThresholdQLearner:
    """
    상태: (트래픽 수준 0~2, 알림 빈도 0~2, 오탐 의심 0~1) → 27가지
    행동: 0=임계값 낮춤(-10%), 1=유지, 2=임계값 높임(+10%)
    """

    STATE_BINS = 3
    N_ACTIONS = 3

    def __init__(self, lr=0.1, gamma=0.9, epsilon=0.3):
        self.lr = lr
        self.gamma = gamma
        self.epsilon = epsilon
        self.q_table = np.zeros((self.STATE_BINS ** 3, self.N_ACTIONS))
        self.threshold_multiplier = 1.0
        self.history = deque(maxlen=200)
        self._step = 0

    def _state_index(self, pps, alert_rate, fp_rate):
        t = min(int(pps / 500), 2)
        a = min(int(alert_rate / 5), 2)
        f = 1 if fp_rate > 0.4 else 0
        return t * 9 + a * 3 + f

    def act(self, pps, alert_rate, fp_rate):
        state = self._state_index(pps, alert_rate, fp_rate)
        if random.random() < self.epsilon:
            return random.randint(0, self.N_ACTIONS - 1)
        return int(np.argmax(self.q_table[state]))

    def update(self, pps, alert_rate, fp_rate, action, reward,
               next_pps, next_ar, next_fp):
        s = self._state_index(pps, alert_rate, fp_rate)
        ns = self._state_index(next_pps, next_ar, next_fp)
        td = reward + self.gamma * np.max(self.q_table[ns]) - self.q_table[s, action]
        self.q_table[s, action] += self.lr * td
        self.epsilon = max(0.05, self.epsilon * 0.9995)
        self._step += 1

    def apply_action(self, action):
        if action == 0:
            self.threshold_multiplier = max(0.3, self.threshold_multiplier * 0.9)
        elif action == 2:
            self.threshold_multiplier = min(3.0, self.threshold_multiplier * 1.1)
        return self.threshold_multiplier

    def get_status(self):
        return {
            "threshold_multiplier": round(self.threshold_multiplier, 3),
            "epsilon": round(self.epsilon, 4),
            "steps": self._step,
            "q_table_max": float(np.max(self.q_table)),
            "experimental": True,
        }


def compute_reward(result, action) -> float:
    """원본 보상 함수. 외부 정답이 아니라 모델 자신의 출력을 본다 — 위 2번 참조."""
    reward = 0.0
    threats = result.get("summary", {}).get("threats", [])
    if threats:
        reward += 5.0
        if action == 0:
            reward += 2.0
    else:
        if action == 2:
            reward += 1.0
        elif action == 0:
            reward -= 2.0
    return reward
