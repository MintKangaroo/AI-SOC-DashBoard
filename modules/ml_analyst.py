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
import json
import os
import threading
import time
from collections import deque
from datetime import datetime

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from modules.ml_feature_store import MLFeatureStore

from modules.logging_setup import get_logger

_log = get_logger(__name__)

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

# 실트래픽 재학습 — scripts/eval_ml.py 의 MIN_FEATURES_FOR_RETRAIN 과 같은 값.
# 3초 주기 피처 3,000건 = 약 2.5시간 가동분. 그보다 적으면 하루 중 한 시간대의
# 프로파일만 배워 다른 시간대를 전부 이상으로 본다.
MIN_REAL_SAMPLES = 3000
# 오염률은 **측정값이 아니라 가정**이다. 비지도 학습이라 "실트래픽의 몇 %가
# 이상인가"를 알 수 없고, 이 값이 곧 이상 판정 비율이 된다. 5% 로 두고 메타데이터에
# 남겨 나중에 라벨이 생기면 다시 정한다. 합성 부트스트랩의 8% 보다 낮게 잡은 이유:
# 실트래픽에서는 8% 가 하루 2시간을 '이상'으로 만든다.
REAL_CONTAMINATION = 0.05
REAL_MODEL = "iso_forest_real.pkl"
REAL_SCALER = "scaler_real.pkl"
REAL_META = "iso_forest_real.json"


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

    def __init__(self, socketio, feature_store=None, demo=False, config=None):
        self.socketio = socketio
        self.running = False
        self.demo = demo
        self._lock = threading.Lock()
        cfg = config or {}
        self.auto_retrain = str(cfg.get("ML_AUTO_RETRAIN", "True")) == "True"
        self.auto_check_seconds = max(30.0, float(cfg.get("ML_AUTO_RETRAIN_CHECK_MINUTES", 10)) * 60)
        self.auto_interval_seconds = max(3600.0, float(cfg.get("ML_AUTO_RETRAIN_INTERVAL_HOURS", 24)) * 3600)
        self._retrain_lock = threading.Lock()

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
            "real_model":    None,          # 실트래픽 모델 메타데이터(있을 때)
            # 현재 모델로 분석한 건수·이상 건수. 재학습 시 0 부터 다시 센다 —
            # 누적 카운터는 옛 모델의 판정과 섞여 "이 모델이 얼마나 자주 이상이라
            # 하는가"를 못 보여준다(실측: 합성 모델 48% → 실모델 0%).
            "since_model":   {"analyses": 0, "anomalies": 0, "since": None},
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
            _log.error(f"[MLAnalyst] 피처 플러시 실패: {e}")

    def _origin_of(self, stats: dict) -> str:
        """이 피처가 실트래픽인가 합성인가 — **설정이 아니라 실제 출처**로 정한다.

        DEMO_MODE=False 로 띄워도 PyShark·Scapy 가 없으면 PacketAnalyzer 는
        조용히 합성 루프로 돈다. 그때 origin 을 self.demo(=설정)로 정하면
        합성 트래픽이 'real' 로 저장되고, eval_ml.py 가 그 수를 실트래픽으로
        세어 "재학습 가능"을 선언한다 — 데모 생성기를 학습하게 된다.
        그래서 공급자가 알려준 source_mode 를 우선한다.
        """
        mode = (stats or {}).get("source_mode")
        if mode in ("real", "demo"):
            return mode
        # 공급자가 안 알려주면 설정으로 되돌아간다(구버전 호출자 호환).
        return "demo" if self.demo else "real"

    def feed_traffic(self, stats: dict):
        """PacketAnalyzer 통계를 피처로 변환해 버퍼에 넣고 영속화한다."""
        feat = self._extract_features(stats)
        with self._lock:
            self._feature_buffer.append(feat)
        # 저장 실패가 분석을 멈추면 안 된다 — 기록은 부가 기능이다.
        try:
            self.store.record(feat, origin=self._origin_of(stats))
        except Exception as e:
            _log.error(f"[MLAnalyst] 피처 기록 실패: {e}")
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
        real = int((out["feature_store"] or {}).get("real") or 0)
        out["retrain"] = {"min_samples": MIN_REAL_SAMPLES, "have": real,
                          "ready": real >= MIN_REAL_SAMPLES,
                          "contamination": REAL_CONTAMINATION,
                          "auto": self.auto_retrain,
                          "auto_interval_hours": self.auto_interval_seconds / 3600}
        return out

    # ──────────────────── 실트래픽 재학습 ────────────────────

    def retrain_from_store(self, min_samples=MIN_REAL_SAMPLES,
                           contamination=REAL_CONTAMINATION, force=False):
        """피처 저장소의 **실트래픽(origin=real)** 만으로 IF 를 다시 학습한다.

        - demo 피처는 절대 섞지 않는다(합성 생성기를 학습하게 된다).
        - pps·bps 가 둘 다 0 인 창은 뺀다. 캡처가 죽어 있던 구간이 '정상 프로파일'
          이 되면 살아 있는 트래픽 전부가 이상으로 보인다(실측: 표준입력 캡처 사고).
        - 시간순 뒤쪽 20% 를 홀드아웃으로 두고 앞 80% 로 학습해 홀드아웃 이상률을
          잰다. 라벨이 없으니 정확도가 아니라 **분포 이동의 냄새**를 보는 것이다 —
          오염률 가정보다 훨씬 높으면 학습 구간이 대표성이 없다는 뜻이다.
        - 그 뒤 전체로 다시 학습해 저장한다. 메타데이터(json)에 표본 수·구간·
          오염률·홀드아웃 이상률·sklearn 버전을 남긴다 — 이 숫자만이 이 모델에
          대해 주장할 수 있는 전부다.
        """
        try:
            self.store.flush()
        except Exception:
            pass
        rows = self.store.load(origin="real")
        X_all = np.array([r[2:] for r in rows], dtype=np.float32) if rows else np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32)
        live = (X_all[:, 0] > 0) | (X_all[:, 1] > 0) if len(X_all) else np.zeros(0, dtype=bool)
        X = X_all[live]
        dropped_zero = int(len(X_all) - len(X))
        if len(X) < min_samples and not force:
            return {"ok": False, "reason": "insufficient_real_features",
                    "have": int(len(X)), "need": int(min_samples), "dropped_zero": dropped_zero,
                    "detail": f"실트래픽 피처 {len(X):,}건 — 최소 {min_samples:,}건 필요"
                              f"({max(0, min_samples - len(X)):,}건 부족, 3초 주기로 약 "
                              f"{max(0, min_samples - len(X)) * 3 / 3600:.1f}시간 가동분)"}
        if len(X) < 50:
            return {"ok": False, "reason": "too_few_for_holdout", "have": int(len(X)),
                    "detail": "홀드아웃을 나눌 수 없을 만큼 적다(50건 미만)"}

        contamination = float(contamination)
        split = int(len(X) * 0.8)
        X_tr, X_ho = X[:split], X[split:]
        sc = StandardScaler().fit(X_tr)
        probe = IsolationForest(n_estimators=200, contamination=contamination,
                                random_state=42, n_jobs=-1).fit(sc.transform(X_tr))
        holdout_rate = float(np.mean(probe.predict(sc.transform(X_ho)) == -1))

        scaler = StandardScaler().fit(X)
        model = IsolationForest(n_estimators=200, contamination=contamination,
                                random_state=42, n_jobs=-1).fit(scaler.transform(X))
        train_rate = float(np.mean(model.predict(scaler.transform(X)) == -1))

        live_rows = [r for r, keep in zip(rows, live) if keep]
        meta = {
            "trained_on": "real", "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "n_samples": int(len(X)), "dropped_zero": dropped_zero,
            "span": [live_rows[0][0], live_rows[-1][0]],
            "contamination": contamination, "contamination_is_assumption": True,
            "holdout_fraction": 0.2, "holdout_anomaly_rate": round(holdout_rate, 4),
            "train_anomaly_rate": round(train_rate, 4),
            "distribution_shift_suspected": bool(holdout_rate > contamination * 3),
            "features": list(FEATURE_NAMES), "sklearn": sklearn.__version__,
            "forced": bool(force and len(X) < min_samples),
        }
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(model, os.path.join(MODEL_DIR, REAL_MODEL))
        joblib.dump(scaler, os.path.join(MODEL_DIR, REAL_SCALER))
        with open(os.path.join(MODEL_DIR, REAL_META), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

        with self._lock:
            self.iso_forest, self.scaler = model, scaler
            self.stats["trained_on"] = "real"
            self.stats["real_model"] = meta
            self.stats["model_status"] = "정상 운영 (실트래픽)"
            self.stats["training_done"] = True
            self.stats["since_model"] = {"analyses": 0, "anomalies": 0, "since": meta["trained_at"]}
        _log.info(f"[MLAnalyst] IF 실트래픽 재학습: {meta['n_samples']:,}건 "
                  f"({meta['span'][0]} ~ {meta['span'][1]}), 홀드아웃 이상률 {holdout_rate:.1%}")
        try:
            self.socketio.emit("ml_model_ready", {
                "message": f"IF 실트래픽 재학습 완료 ({meta['n_samples']:,}건)",
                "models": ["Isolation Forest"], "trained_on": "real",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })
        except Exception:
            pass
        return {"ok": True, **meta}

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
            _log.error(f"[MLAnalyst] 모델 초기화 오류: {e}")
            return

        threading.Thread(target=self._analysis_loop, daemon=True).start()
        if self.auto_retrain:
            threading.Thread(target=self._auto_retrain_loop, daemon=True,
                             name="ml-auto-retrain").start()

    # ──────────────────── 자동 재학습 ────────────────────

    def auto_retrain_due(self, now=None):
        """지금 자동 재학습을 해야 하는가. (해야 하면 이유, 아니면 None)

        - 실모델이 없고 실피처가 MIN 이상 → 첫 학습
        - 실모델이 있고 학습한 지 INTERVAL 이 지났고 실피처가 MIN 이상 → 갱신
        """
        try:
            have = int(self.store.count("real"))
        except Exception:
            return None
        if have < MIN_REAL_SAMPLES:
            return None
        meta = self.stats.get("real_model")
        if not meta:
            return "first_real_model"
        try:
            trained_at = datetime.strptime(meta.get("trained_at", ""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "refresh"
        age = ((now or datetime.now()) - trained_at).total_seconds()
        return "refresh" if age >= self.auto_interval_seconds else None

    def _auto_retrain_loop(self):
        while self.running:
            time.sleep(self.auto_check_seconds)
            if not self.running:
                break
            try:
                why = self.auto_retrain_due()
                if not why:
                    continue
                if not self._retrain_lock.acquire(blocking=False):   # 수동 재학습과 겹치면 건너뜀
                    continue
                try:
                    _log.info(f"[MLAnalyst] 자동 재학습 시작 ({why})")
                    r = self.retrain_from_store()
                    if not r.get("ok"):
                        _log.warning(f"[MLAnalyst] 자동 재학습 안 함: {r.get('detail') or r.get('reason')}")
                finally:
                    self._retrain_lock.release()
            except Exception as e:
                _log.error(f"[MLAnalyst] 자동 재학습 루프 오류: {e}")

    def _train_isolation_forest(self):
        # 실트래픽으로 학습한 모델이 있으면 그것이 우선이다.
        real_model = os.path.join(MODEL_DIR, REAL_MODEL)
        real_scaler = os.path.join(MODEL_DIR, REAL_SCALER)
        real_meta = os.path.join(MODEL_DIR, REAL_META)
        if os.path.exists(real_model) and os.path.exists(real_scaler):
            try:
                model, scaler = joblib.load(real_model), joblib.load(real_scaler)
                meta = None
                if os.path.exists(real_meta):
                    with open(real_meta, encoding="utf-8") as f:
                        meta = json.load(f)
                with self._lock:
                    self.iso_forest, self.scaler = model, scaler
                    self.stats["trained_on"] = "real"
                    self.stats["real_model"] = meta
                _log.info("[MLAnalyst] IF 실트래픽 모델 로드"
                          + (f" ({meta['n_samples']:,}건, {meta['trained_at']})" if meta else ""))
                return
            except Exception as e:
                _log.warning(f"[MLAnalyst] 실트래픽 모델 로드 실패({e}) — 합성 부트스트랩으로")

        model_path = os.path.join(MODEL_DIR, "iso_forest.pkl")
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.iso_forest = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                return
            except Exception as e:
                # sklearn 버전 불일치 등으로 로드 실패 → 재학습
                _log.warning(f"[MLAnalyst] IF 모델 로드 실패({e}) — 재학습")

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
        with self._lock:
            sm = self.stats["since_model"]
            sm["analyses"] += 1
            if anomaly:
                self.stats["if_anomalies"] += 1
                sm["anomalies"] += 1
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
