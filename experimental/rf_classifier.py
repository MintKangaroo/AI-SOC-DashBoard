"""Random Forest 6클래스 위협 분류기 (실험적 — 비활성).

`modules/ml_analyst.py` 에서 이관.

## 격리 사유

1. **라벨이 없다.** 지도학습 분류기인데 전 시스템의 사람 판정 라벨이 1건이다
   (`alerts.db` verdict_actor='mintkangaroo' 1건; 아카이브 110,748건은 전부
   UNREVIEWED). 학습도 검증도 불가능하다.
2. **학습 분포 밖에서 자신 있게 틀린다.** 합성 6클래스는 서로 겹치지 않는
   uniform 상자다. 실제 트래픽은 어느 상자에도 속하지 않지만, 랜덤 포레스트의
   트리는 항상 투표하므로 OOD 입력에서도 높은 confidence 를 출력한다.
   원본의 위협 판정 조건이 `confidence >= 80` 이었으므로, 이 조건은 실트래픽에서
   필터 역할을 하지 못한다.
3. **출력이 아무 판단에도 쓰이지 않았다.** `soar.py` / `threat_detector.py` 에
   이 분류 결과를 읽는 코드가 없다. SocketIO 로 ML 패널에 그려지고 끝이었다.

## 복귀 조건

클래스당 실제 라벨 30건 이상(총 180건+)이 `alerts.db` 의 `verdict` 컬럼에
`verdict_actor` = 사람 계정으로 쌓이고, `scripts/eval_ml.py` 가 룰 베이스라인
대비 우위를 숫자로 보일 것.
"""
import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from experimental.synthetic_data import THREAT_LABELS, generate_training_data

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "models")


def train(model_path=None, scaler=None):
    """합성 데이터로 RF 를 학습해 반환한다. scaler 를 주지 않으면 새로 fit 한다.

    주의: 원본 구현은 `MLAnalyst.scaler`(정상 200샘플로 fit)를 재사용했다.
    여기서 scaler 를 인자로 받는 이유는, 실험 코드가 제품 코드의 스케일러를
    **덮어쓰지 못하게** 하기 위해서다 (원본의 scaler 재fit 버그 참조).
    """
    model_path = model_path or os.path.join(MODEL_DIR, "rf_classifier.pkl")
    X, y = generate_training_data()
    if scaler is None:
        scaler = StandardScaler().fit(X[:200])
    clf = RandomForestClassifier(
        n_estimators=300, max_depth=12, random_state=42, n_jobs=-1,
    ).fit(scaler.transform(X), y)
    joblib.dump(clf, model_path)
    return clf, scaler


def load(model_path=None):
    """캐시된 모델을 로드한다. 없거나 버전 불일치면 None."""
    model_path = model_path or os.path.join(MODEL_DIR, "rf_classifier.pkl")
    if not os.path.exists(model_path):
        return None
    try:
        return joblib.load(model_path)
    except Exception:
        return None


def predict(clf, scaler, feat):
    """단일 피처 벡터에 대한 분류 결과. 원본 `_run_all_models` 의 RF 분기와 동일."""
    scaled = scaler.transform(np.asarray(feat, dtype=np.float32).reshape(1, -1))
    pred_cls = int(clf.predict(scaled)[0])
    proba = clf.predict_proba(scaled)[0]
    return {
        "predicted_class": pred_cls,
        "label": THREAT_LABELS.get(pred_cls, "UNKNOWN"),
        "confidence": round(float(np.max(proba)) * 100, 1),
        "probabilities": {
            THREAT_LABELS[i]: round(float(p) * 100, 1) for i, p in enumerate(proba)
        },
        "experimental": True,
    }
