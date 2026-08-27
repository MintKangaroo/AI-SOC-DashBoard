"""LSTM Autoencoder 시계열 이상탐지 (실험적 — 비활성).

`modules/ml_analyst.py` 에서 이관.

## 격리 사유

1. **학습 데이터에 시간 구조가 없다.** 학습 시퀀스 400개는 각 타임스텝을
   독립적으로 뽑은 uniform 난수다(`synthetic_data.generate_normal_sequences`).
   LSTM 오토인코더는 시간 의존성을 재구성하는 구조인데, 재구성할 시간 의존성이
   데이터에 존재하지 않는다. 이 모델이 수렴해서 배우는 것은 피처별 평균이며,
   그것은 `np.mean` 한 줄과 같다. **샘플 수를 늘려도 해소되지 않는 문제다.**
2. **현재 실행되지 않는다.** `requirements.txt` 에서 tensorflow 가 주석 처리되어
   있고 실행 환경에 설치되어 있지 않다. 원본에서 `TF_AVAILABLE = False` 이므로
   학습·추론 분기가 통째로 건너뛰어졌다. `data/models/lstm_autoencoder.keras`
   (821KB) 는 과거 다른 환경에서 만들어진 고아 파일이다.
3. **제품 코드의 스케일러를 오염시켰다.** 원본 `_train_lstm_autoencoder()` 는
   `self.scaler.fit(flat)` 로 Isolation Forest 와 Random Forest 가 학습에 사용한
   스케일러를 덮어썼다(주석은 "이미 fit 됐지만 재확인"이었으나 `StandardScaler.fit`
   은 mean/std 를 교체한다). 캐시가 없는 최초 실행이나 `.keras` 로드 실패 시
   IF/RF 의 입력 분포가 조용히 어긋났다. **이 모듈을 분리하면서 해당 버그가 함께
   제거된다.**

## 복귀 조건

`data/ml_features.db` 에 실제 트래픽 피처가 연속 구간으로 충분히 쌓이고
(최소 수만 스텝 — 시간 구조를 학습하려면 실제 주기성이 데이터에 있어야 한다),
tensorflow 를 정식 의존성으로 승격할 근거가 생길 것. 그 전까지는 Isolation Forest
로 충분하다.
"""
import os

import numpy as np

try:
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "models")

SEQ_LEN = 30
N_FEATURES = 8


def build(seq_len=SEQ_LEN, n_features=N_FEATURES):
    if not TF_AVAILABLE:
        return None
    inp = keras.Input(shape=(seq_len, n_features))
    x = layers.LSTM(64, return_sequences=True)(inp)
    x = layers.LSTM(32)(x)
    encoded = layers.Dense(16, activation="relu")(x)
    x = layers.RepeatVector(seq_len)(encoded)
    x = layers.LSTM(32, return_sequences=True)(x)
    x = layers.LSTM(64, return_sequences=True)(x)
    decoded = layers.TimeDistributed(layers.Dense(n_features))(x)
    model = keras.Model(inp, decoded)
    model.compile(optimizer="adam", loss="mse")
    return model


def train(scaler, model_path=None, seq_len=SEQ_LEN):
    """정상 시퀀스로 학습. `scaler` 는 **읽기 전용으로만** 쓴다 (재fit 금지)."""
    if not TF_AVAILABLE:
        return None
    from experimental.synthetic_data import generate_normal_sequences

    model_path = model_path or os.path.join(MODEL_DIR, "lstm_autoencoder.keras")
    seqs = generate_normal_sequences(seq_len=seq_len)
    flat = seqs.reshape(-1, seqs.shape[-1])
    scaled = scaler.transform(flat).reshape(-1, seq_len, seqs.shape[-1])

    model = build(seq_len, seqs.shape[-1])
    model.fit(scaled, scaled, epochs=15, batch_size=32,
              validation_split=0.1, verbose=0)
    model.save(model_path)
    return model


def load(model_path=None):
    if not TF_AVAILABLE:
        return None
    model_path = model_path or os.path.join(MODEL_DIR, "lstm_autoencoder.keras")
    if not os.path.exists(model_path):
        return None
    try:
        return keras.models.load_model(model_path)
    except Exception:
        return None


def score(model, scaler, seq, threshold=0.05, seq_len=SEQ_LEN):
    """재구성 오차 기반 이상 판정. 원본 `_run_all_models` 의 LSTM 분기와 동일."""
    seq_np = np.asarray(seq[-seq_len:], dtype=np.float32)
    scaled = scaler.transform(seq_np).reshape(1, seq_len, -1)
    reconstructed = model.predict(scaled, verbose=0)
    mse = float(np.mean((scaled - reconstructed) ** 2))
    return {
        "reconstruction_error": round(mse, 6),
        "threshold": round(threshold, 6),
        "anomaly": bool(mse > threshold),
        "label": "시계열 이상" if mse > threshold else "정상 패턴",
        "experimental": True,
    }
