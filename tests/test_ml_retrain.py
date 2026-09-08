"""IF 실트래픽 재학습 경로 — 표본 부족 거부·demo 제외·캡처 공백 제외·메타데이터·기동 시 우선 로드."""
import json
import os

import numpy as np
import pytest

from modules import ml_analyst as ma
from modules.ml_feature_store import MLFeatureStore


class FakeSocketIO:
    def __init__(self): self.events = []
    def emit(self, event, data=None, **kw): self.events.append((event, data))


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(ma, "MODEL_DIR", str(tmp_path / "models"))
    store = MLFeatureStore(db_path=str(tmp_path / "feat.db"), flush_every=50)
    a = ma.MLAnalyst(FakeSocketIO(), feature_store=store, demo=False)
    a._train_isolation_forest()          # 합성 부트스트랩
    yield a, store
    store.close()


def _fill(store, n, origin="real", seed=0, zero=0):
    rng = np.random.RandomState(seed)
    for _ in range(n):
        feat = np.array([rng.uniform(50, 400), rng.uniform(2e4, 3e5), rng.uniform(.5, .8),
                         rng.uniform(.1, .3), rng.uniform(.01, .05), rng.randint(1, 20),
                         rng.randint(1, 15), rng.uniform(200, 1200)], dtype=np.float32)
        store.record(feat, origin=origin)
    for _ in range(zero):
        store.record(np.zeros(8, dtype=np.float32), origin=origin)
    store.flush()


def test_refuses_when_real_features_are_insufficient(env):
    a, store = env
    _fill(store, 120)
    r = a.retrain_from_store()
    assert r["ok"] is False and r["reason"] == "insufficient_real_features"
    assert r["have"] == 120 and r["need"] == ma.MIN_REAL_SAMPLES
    assert a.stats["trained_on"] == "synthetic", "거부됐는데 모델이 바뀌면 안 된다"
    assert not os.path.exists(os.path.join(ma.MODEL_DIR, ma.REAL_MODEL))


def test_demo_features_never_count_and_never_train(env):
    a, store = env
    _fill(store, 5000, origin="demo")
    _fill(store, 200, origin="real")
    r = a.retrain_from_store()
    assert r["ok"] is False and r["have"] == 200   # demo 5,000건은 없는 셈
    r = a.retrain_from_store(force=True)
    assert r["ok"] and r["n_samples"] == 200 and r["forced"] is True


def test_capture_gap_windows_are_dropped(env):
    a, store = env
    _fill(store, 300, zero=40)
    r = a.retrain_from_store(min_samples=100)
    assert r["ok"] and r["dropped_zero"] == 40 and r["n_samples"] == 300


def test_retrain_writes_model_and_metadata_and_swaps_live_model(env):
    a, store = env
    _fill(store, 400)
    before = a.iso_forest
    r = a.retrain_from_store(min_samples=100, contamination=0.04)
    assert r["ok"] and a.iso_forest is not before
    assert a.stats["trained_on"] == "real" and a.stats["real_model"]["n_samples"] == 400
    assert 0.0 <= r["holdout_anomaly_rate"] <= 1.0 and r["contamination"] == 0.04
    assert r["contamination_is_assumption"] is True
    meta = json.load(open(os.path.join(ma.MODEL_DIR, ma.REAL_META), encoding="utf-8"))
    assert meta["n_samples"] == 400 and meta["features"] == list(ma.FEATURE_NAMES)
    assert meta["span"][0] <= meta["span"][1]
    assert any(e[0] == "ml_model_ready" and e[1]["trained_on"] == "real" for e in a.socketio.events)
    assert a.get_stats()["retrain"]["have"] == 400


def test_new_instance_prefers_real_model_on_startup(env, tmp_path):
    a, store = env
    _fill(store, 300)
    assert a.retrain_from_store(min_samples=100)["ok"]
    b = ma.MLAnalyst(FakeSocketIO(), feature_store=store, demo=False)
    b._train_isolation_forest()
    assert b.stats["trained_on"] == "real" and b.stats["real_model"]["n_samples"] == 300
    # 실모델로 분석한 결과도 그 출처를 말한다
    out = b._run_models(np.array([100, 5e4, .6, .3, .02, 5, 5, 600], dtype=np.float32))
    assert out["trained_on"] == "real" and out["summary"]["advisory_only"] is True


def test_distribution_shift_flag_when_holdout_looks_different(env):
    """앞 80% 와 전혀 다른 뒤 20% — 홀드아웃 이상률이 오염률의 3배를 넘으면 표시한다."""
    a, store = env
    _fill(store, 400, seed=1)
    rng = np.random.RandomState(9)
    for _ in range(100):
        store.record(np.array([rng.uniform(5000, 9000), rng.uniform(5e6, 9e6), .1, .1, .8,
                               rng.randint(300, 900), rng.randint(200, 900), 60], dtype=np.float32), origin="real")
    store.flush()
    r = a.retrain_from_store(min_samples=100, contamination=0.02)
    assert r["ok"] and r["distribution_shift_suspected"] is True


def test_eval_script_reports_model_state(tmp_path, monkeypatch):
    import importlib, sys
    sys.path.insert(0, str(ma.MODEL_DIR and os.path.dirname(os.path.dirname(ma.__file__))))
    ev = importlib.import_module("scripts.eval_ml") if "scripts.eval_ml" not in sys.modules else sys.modules["scripts.eval_ml"]
    monkeypatch.setattr(ev, "REPO", str(tmp_path))
    assert ev.model_state()["trained_on"] == "synthetic"
    d = tmp_path / "data" / "models"; d.mkdir(parents=True)
    (d / "iso_forest_real.json").write_text(json.dumps({"n_samples": 3200, "span": ["a", "b"], "trained_at": "t",
                                                         "contamination": 0.05, "holdout_anomaly_rate": 0.2,
                                                         "distribution_shift_suspected": True}), encoding="utf-8")
    ms = ev.model_state()
    assert ms["trained_on"] == "real" and "분포 이동" in ms["detail"] and "3,200" in ms["detail"]


def test_auto_retrain_due_logic(env):
    from datetime import datetime, timedelta
    a, store = env
    assert a.auto_retrain_due() is None                      # 피처 없음
    _fill(store, 120)
    assert a.auto_retrain_due() is None                      # MIN 미만
    a.store.count = lambda origin=None: 5000                 # MIN 이상으로 가장
    assert a.auto_retrain_due() == "first_real_model"        # 실모델 없음 → 첫 학습
    a.stats["real_model"] = {"trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    assert a.auto_retrain_due() is None                      # 방금 학습 → 대기
    old = (datetime.now() - timedelta(hours=25)).strftime("%Y-%m-%d %H:%M:%S")
    a.stats["real_model"] = {"trained_at": old}
    assert a.auto_retrain_due() == "refresh"                 # 24h 경과 → 갱신


def test_auto_retrain_config_is_read(tmp_path):
    s = MLFeatureStore(db_path=str(tmp_path / "f.db"))
    try:
        a = ma.MLAnalyst(FakeSocketIO(), feature_store=s, config={
            "ML_AUTO_RETRAIN": "False", "ML_AUTO_RETRAIN_CHECK_MINUTES": "1",
            "ML_AUTO_RETRAIN_INTERVAL_HOURS": "6"})
        assert a.auto_retrain is False and a.auto_check_seconds == 60 and a.auto_interval_seconds == 6 * 3600
        assert a.get_stats()["retrain"]["auto"] is False
    finally:
        s.close()
