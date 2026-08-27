"""
ML 보안 분석 모듈 — 자체 이상탐지
─────────────────────────────────
Isolation Forest 기반 비지도 트래픽 이상탐지 1종만 운영한다.

과거 이 모듈에는 Random Forest(지도 분류) · LSTM Autoencoder(시계열) ·
Q-Learning(임계값 튜닝)이 함께 있었으나, 셋 모두 실데이터로 학습·검증된 적이 없고
출력이 어떤 판단 경로에도 연결되어 있지 않아 `experimental/` 로 격리했다.
격리 사유와 복귀 조건은 `experimental/README.md` 및 `docs/ml_models.md` 참조.

현재 Isolation Forest 도 **합성 데이터로 학습된 상태**다. 비지도 학습이라 라벨 없이
실트래픽으로 재학습할 수 있는 유일한 모델이라서 남겼을 뿐, 지금 시점의 출력은
정상 프로파일 근사치 이상의 의미가 없다. 성능을 주장하지 않는다.
"""
import os
import threading
import time
from collections import deque
from datetime import datetime

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from modules.ml_feature_store import MLFeatureStore

# ─────────────────────────────────────────
#  Feature 정의 (8개 수치형 피처)
# ─────────────────────────────────────────
FEATURE_NAMES = [
    "pps",              # 패킷/초
    "bps",              # 바이트/초
    "tcp_ratio",        # TCP 비율
    "udp_ratio",        # UDP 비율
    "icmp_ratio",       # ICMP 비율
    "unique_src",       # 고유 출발지 IP 수
    "unique_dst_port",  # 고유 목적지 포트 수
    "avg_pkt_size",     # 평균 패킷 크기
]

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "models")

# 정상 트래픽 부트스트랩 프로파일 — 실데이터가 쌓이기 전까지의 임시 기준.
# `experimental/synthetic_data.py` 의 NORMAL 클래스와 동일한 구간이지만,
# 제품 코드가 experimental 을 import 하지 않도록 의도적으로 분리해 둔다.
_NORMAL_RANGES = [
    (10, 300), (5e3, 5e5), (0.5, 0.8), (0.1, 0.35),
    (0.01, 0.05), (1, 20), (1, 15), (200, 1200),
]
_INT_FEATURES = (5, 6)
_BOOTSTRAP_SAMPLES = 200


def _synthetic_normal_profile(seed=42, n=_BOOTSTRAP_SAMPLES):
    """정상 트래픽 부트스트랩 샘플. 실데이터 재학습 전까지만 쓰인다."""
    rng = np.random.RandomState(seed)
    return np.array([
        [
            rng.randint(lo, hi) if i in _INT_FEATURES else rng.uniform(lo, hi)
            for i, (lo, hi) in enumerate(_NORMAL_RANGES)
        ]
        for _ in range(n)
    ], dtype=np.float32)


class MLAnalyst:
    """트래픽 피처를 받아 Isolation Forest 로 이상 점수를 산출한다."""

    WINDOW = 30   # 피처 슬라이딩 윈도우 길이

    def __init__(self, socketio, feature_store=None, demo=False):
        self.socketio = socketio
        self.running = False
        self.demo = demo
        self._lock = threading.Lock()

        # 트래픽 피처 영속화 — 실트래픽 재학습·평가의 전제 조건.
        # 이게 없으면 모델 입력 공간에 데이터가 한 건도 남지 않는다.
        self.store = feature_store if feature_store is not None else MLFeatureStore()

        # 피처 버퍼 (슬라이딩 윈도우)
        self._feature_buffer = deque(maxlen=self.WINDOW * 2)

        # 모델
        self.iso_forest: IsolationForest = None
        self.scaler: StandardScaler = None

        # 통계
        self.stats = {
            "if_anomalies":  0,
            "analyses":      0,
            "model_status":  "초기화 중...",
            "training_done": False,
            "trained_on":    "synthetic",   # synthetic | real
            "feedback":      {"true_positive": 0, "false_positive": 0},
        }
        self.analysis_log = deque(maxlen=100)

        os.makedirs(MODEL_DIR, exist_ok=True)

    # ──────────────────── 공개 API ────────────────────

    def start(self, demo=None):
        if self.running:
            return
        if demo is not None:
            self.demo = bool(demo)
        self.running = True
        threading.Thread(target=self._init_models, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.store.flush()
        except Exception as e:
            print(f"[MLAnalyst] 피처 플러시 실패: {e}")

    def feed_traffic(self, stats: dict):
        """PacketAnalyzer 통계를 피처로 변환해 버퍼에 넣고 영속화한다."""
        feat = self._extract_features(stats)
        with self._lock:
            self._feature_buffer.append(feat)
        # 저장 실패가 분석을 멈추면 안 된다 — 기록은 부가 기능이다.
        try:
            self.store.record(feat, origin="demo" if self.demo else "real")
        except Exception as e:
            print(f"[MLAnalyst] 피처 기록 실패: {e}")
        return feat

    def analyze_now(self, stats: dict) -> dict:
        """동기 분석 — REST API 호출용"""
        return self._run_models(self._extract_features(stats))

    def get_stats(self) -> dict:
        with self._lock:
            out = dict(self.stats)
        try:
            out["feature_store"] = self.store.stats()
        except Exception:
            out["feature_store"] = {"total": 0, "real": 0, "demo": 0, "pending": 0}
        return out

    def get_log(self, limit=20) -> list:
        with self._lock:
            return list(self.analysis_log)[-limit:]

    def get_rl_status(self) -> dict:
        """호환용. Q-Learning 은 experimental/ 로 격리되어 비활성이다."""
        return {
            "enabled": False,
            "reason": "experimental",
            "detail": "Q-Learning 임계값 튜너는 experimental/threshold_qlearner.py 로 "
                      "격리됨 — 보상에 외부 정답이 없고 출력이 미적용이었음",
        }

    def mark_alert(self, is_fp=False):
        """정탐/오탐 피드백 집계.

        과거에는 이 값이 Q-Learning 의 **상태**에만 반영되고 보상에는 닿지 않았다.
        지금은 학습에 쓰이지 않고 누적 집계만 한다 — 라벨이 충분히 쌓였는지
        판단하는 근거로 쓰기 위해서다. 실제 학습 연결은 라벨 확보 후에 한다.
        """
        key = "false_positive" if is_fp else "true_positive"
        with self._lock:
            self.stats["feedback"][key] += 1

    # ──────────────────── 초기화 / 학습 ────────────────────

    def _init_models(self):
        """앱 시작 시 백그라운드에서 모델 준비"""
        with self._lock:
            self.stats["model_status"] = "학습 중..."
        try:
            self._train_isolation_forest()
            with self._lock:
                self.stats["model_status"] = "정상 운영"
                self.stats["training_done"] = True
            self.socketio.emit("ml_model_ready", {
                "message": "ML 모델 준비 완료 (Isolation Forest)",
                "models": ["Isolation Forest"],
                "trained_on": self.stats["trained_on"],
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })
        except Exception as e:
            with self._lock:
                self.stats["model_status"] = f"오류: {e}"
            print(f"[MLAnalyst] 모델 초기화 오류: {e}")
            return

        threading.Thread(target=self._analysis_loop, daemon=True).start()

    def _train_isolation_forest(self):
        model_path = os.path.join(MODEL_DIR, "iso_forest.pkl")
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.iso_forest = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                return
            except Exception as e:
                # sklearn 버전 불일치 등으로 로드 실패 → 재학습
                print(f"[MLAnalyst] IF 모델 로드 실패({e}) — 재학습")

        normal_X = _synthetic_normal_profile()
        self.scaler = StandardScaler().fit(normal_X)
        self.iso_forest = IsolationForest(
            n_estimators=200, contamination=0.08, random_state=42, n_jobs=-1,
        ).fit(self.scaler.transform(normal_X))

        joblib.dump(self.iso_forest, model_path)
        joblib.dump(self.scaler, scaler_path)

    # ──────────────────── 분석 루프 ────────────────────

    def _analysis_loop(self):
        while self.running:
            time.sleep(3)
            with self._lock:
                if len(self._feature_buffer) < 5:
                    continue
                feat = self._feature_buffer[-1]

            result = self._run_models(feat)

            with self._lock:
                self.analysis_log.append(result)
                self.stats["analyses"] += 1

            self.socketio.emit("ml_analysis", result)

    def _run_models(self, feat) -> dict:
        result = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "features": dict(zip(FEATURE_NAMES, [round(float(v), 3) for v in feat])),
            "trained_on": self.stats.get("trained_on", "synthetic"),
        }

        feat_arr = np.asarray(feat, dtype=np.float32).reshape(1, -1)
        anomaly = False
        ready = self.iso_forest is not None and self.scaler is not None
        result["model_ready"] = ready

        if not ready:
            # 모델 로드 전이다. 이 상태를 '정상'으로 보고하면 모델이 없다는 사실이
            # 정상 판정으로 둔갑한다 — 침묵보다 나쁜 오독이다.
            result["summary"] = {
                "severity": "UNKNOWN", "threats": [], "verdict": "모델 준비 안 됨",
                "advisory_only": True,
            }
            return result

        scaled = self.scaler.transform(feat_arr)
        anomaly = bool(self.iso_forest.predict(scaled)[0] == -1)
        if_score = float(self.iso_forest.score_samples(scaled)[0])
        if anomaly:
            with self._lock:
                self.stats["if_anomalies"] += 1
        result["isolation_forest"] = {
            "anomaly": anomaly,
            "score": round(if_score, 4),
            "label": "이상 탐지" if anomaly else "정상",
        }

        # 단일 모델이므로 합의 규칙 없이 그대로 보고한다.
        # 이 판정은 탐지·차단 경로에 연결되어 있지 않다 (관측 전용).
        result["summary"] = {
            "severity": "LOW" if anomaly else "NORMAL",
            "threats": ["IF이상"] if anomaly else [],
            "verdict": "이상 징후" if anomaly else "정상",
            "advisory_only": True,
        }
        return result

    # ──────────────────── 피처 추출 ────────────────────

    @staticmethod
    def _extract_features(stats: dict) -> np.ndarray:
        total = max(stats.get("total_packets", 1), 1)
        tcp = stats.get("tcp_packets", 0)
        udp = stats.get("udp_packets", 0)
        icmp = stats.get("icmp_packets", 0)
        byt = max(stats.get("total_bytes", 1), 1)

        return np.array([
            float(stats.get("packets_per_sec", 0)),
            float(stats.get("bytes_per_sec", 0)),
            tcp / total,
            udp / total,
            icmp / total,
            float(stats.get("unique_src_ips", 1)),
            float(stats.get("unique_dst_ports", 1)),
            byt / total,
        ], dtype=np.float32)
