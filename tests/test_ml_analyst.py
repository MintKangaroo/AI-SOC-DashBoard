"""ML 스택 테스트 — 이 영역은 감사 시점에 테스트가 0건이었다.

검증 대상:
1. `experimental/` 격리 규칙 (제품 코드가 실험 코드를 import 하지 않을 것)
2. `MLFeatureStore` — 재학습·평가의 전제인 피처 영속화
3. `MLAnalyst` 축소 후의 공개 인터페이스 호환성
4. 합성 데이터가 성능 주장의 근거가 될 수 없다는 사실의 회귀 고정
"""
import pathlib
import re

import numpy as np
import pytest

from modules.ml_analyst import (FEATURE_NAMES, MLAnalyst,
                                _synthetic_normal_profile)
from modules.ml_feature_store import FEATURE_COLUMNS, MLFeatureStore

REPO = pathlib.Path(__file__).resolve().parent.parent


class FakeSocketIO:
    def __init__(self):
        self.events = []

    def emit(self, event, data=None, **kwargs):
        self.events.append((event, data))


@pytest.fixture
def store(tmp_path):
    s = MLFeatureStore(db_path=str(tmp_path / "feat.db"), flush_every=3)
    yield s
    s.close()


@pytest.fixture
def analyst(tmp_path):
    s = MLFeatureStore(db_path=str(tmp_path / "feat.db"), flush_every=1)
    a = MLAnalyst(FakeSocketIO(), feature_store=s, demo=True)
    a._train_isolation_forest()
    yield a
    s.close()


def _stats(pps=120, bps=60000, total=1000, tcp=800, udp=150, icmp=50,
           byt=500000, src=5, ports=7):
    return {
        "total_packets": total, "tcp_packets": tcp, "udp_packets": udp,
        "icmp_packets": icmp, "total_bytes": byt, "packets_per_sec": pps,
        "bytes_per_sec": bps, "unique_src_ips": src, "unique_dst_ports": ports,
    }


# ─────────── 1. experimental/ 격리 규칙 ───────────

def test_production_code_never_imports_experimental():
    """제품 코드가 experimental/ 을 import 하면 격리가 무의미해진다."""
    pattern = re.compile(r"^\s*(?:from|import)\s+experimental\b", re.M)
    offenders = []
    for sub in ("modules", "api"):
        for path in (REPO / sub).rglob("*.py"):
            if pattern.search(path.read_text(encoding="utf-8")):
                offenders.append(str(path.relative_to(REPO)))
    for name in ("app.py", "wiring.py", "config.py"):
        if pattern.search((REPO / name).read_text(encoding="utf-8")):
            offenders.append(name)
    assert offenders == [], f"제품 코드가 experimental 을 import 함: {offenders}"


def test_experimental_never_imports_product_modules():
    """반대 방향도 막는다 — 실험 코드가 제품 상태를 건드리지 못하게."""
    pattern = re.compile(r"^\s*(?:from|import)\s+modules\b", re.M)
    offenders = [
        str(p.relative_to(REPO))
        for p in (REPO / "experimental").rglob("*.py")
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"experimental 이 modules 를 import 함: {offenders}"


def test_experimental_modules_exist_and_document_reasons():
    """격리된 모듈은 사유를 문서화한다 — 조용한 삭제와 구분되어야 한다."""
    for name in ("rf_classifier", "lstm_autoencoder", "threshold_qlearner"):
        path = REPO / "experimental" / f"{name}.py"
        assert path.exists(), f"{name} 이 experimental/ 에 없음"
        text = path.read_text(encoding="utf-8")
        assert "격리 사유" in text and "복귀 조건" in text


# ─────────── 2. MLFeatureStore ───────────

def test_feature_store_records_and_reads_back(store):
    feat = np.arange(len(FEATURE_COLUMNS), dtype=np.float32)
    for _ in range(3):
        assert store.record(feat, origin="real") is True
    store.flush()
    rows = store.load()
    assert len(rows) == 3
    # (ts, origin, *features)
    assert rows[0][1] == "real"
    assert list(rows[0][2:]) == [float(v) for v in feat]


def test_feature_store_rejects_wrong_arity(store):
    assert store.record([1.0, 2.0]) is False
    assert store.record(None) is False
    store.flush()
    assert store.count() == 0


def test_feature_store_separates_real_and_demo(store):
    feat = np.ones(len(FEATURE_COLUMNS), dtype=np.float32)
    store.record(feat, origin="real")
    store.record(feat, origin="demo")
    store.record(feat, origin="demo")
    store.flush()
    assert store.count(origin="real") == 1
    assert store.count(origin="demo") == 2
    s = store.stats()
    assert s["total"] == 3 and s["real"] == 1 and s["demo"] == 2


def test_feature_store_batches_writes(store):
    """flush_every=3 — 2건까지는 pending, 3건째에 커밋된다."""
    feat = np.zeros(len(FEATURE_COLUMNS), dtype=np.float32)
    store.record(feat)
    store.record(feat)
    assert store.stats()["pending"] == 2
    assert store.count() == 0          # 아직 디스크에 없음
    store.record(feat)
    assert store.stats()["pending"] == 0
    assert store.count() == 3


def test_feature_store_purge_keeps_recent(store):
    feat = np.zeros(len(FEATURE_COLUMNS), dtype=np.float32)
    store.record(feat, ts="2020-01-01 00:00:00")
    store.record(feat, ts="2020-01-02 00:00:00")
    store.record(feat)                  # 지금
    store.flush()
    assert store.purge_older_than(365) == 2
    assert store.count() == 1


def test_feature_store_survives_reopen(tmp_path):
    path = str(tmp_path / "feat.db")
    s1 = MLFeatureStore(db_path=path, flush_every=1)
    s1.record(np.ones(len(FEATURE_COLUMNS), dtype=np.float32))
    s1.close()
    s2 = MLFeatureStore(db_path=path)
    assert s2.count() == 1
    s2.close()


# ─────────── 3. MLAnalyst 인터페이스 호환성 ───────────

def test_feed_traffic_persists_feature(analyst):
    analyst.feed_traffic(_stats())
    assert analyst.store.count() == 1
    row = analyst.store.load()[0]
    assert row[1] == "demo"             # demo=True 로 만들었으므로
    assert len(row) == 2 + len(FEATURE_NAMES)


def test_feed_traffic_survives_store_failure(analyst):
    """기록은 부가 기능이다 — 저장이 깨져도 분석은 계속되어야 한다."""
    class BrokenStore:
        def record(self, *a, **k):
            raise RuntimeError("디스크 오류")

        def stats(self):
            raise RuntimeError("디스크 오류")

    analyst.store = BrokenStore()
    feat = analyst.feed_traffic(_stats())
    assert feat is not None and len(feat) == len(FEATURE_NAMES)
    assert analyst.get_stats()["feature_store"]["total"] == 0


def test_public_interface_preserved(analyst):
    """축소 후에도 호출부(api/, soar.py, ai_analyst.py)가 쓰는 메서드는 남아야 한다."""
    for name in ("start", "stop", "feed_traffic", "analyze_now",
                 "get_stats", "get_log", "get_rl_status", "mark_alert"):
        assert callable(getattr(analyst, name)), f"{name} 누락"


def test_rl_status_reports_disabled(analyst):
    """Q-Learning 은 격리됐다 — 활성인 척하면 안 된다."""
    rl = analyst.get_rl_status()
    assert rl["enabled"] is False
    assert rl["reason"] == "experimental"


def test_mark_alert_accumulates_labels(analyst):
    analyst.mark_alert(is_fp=False)
    analyst.mark_alert(is_fp=True)
    analyst.mark_alert(is_fp=True)
    fb = analyst.get_stats()["feedback"]
    assert fb == {"true_positive": 1, "false_positive": 2}


def test_analysis_result_is_advisory_only(analyst):
    """ML 판정은 탐지·차단 경로에 연결되어 있지 않다. 그 사실을 결과가 밝혀야 한다."""
    result = analyst.analyze_now(_stats())
    assert result["summary"]["advisory_only"] is True
    assert result["trained_on"] == "synthetic"
    assert "isolation_forest" in result
    assert set(result["features"]) == set(FEATURE_NAMES)


def test_retired_models_absent_from_result(analyst):
    """RF/LSTM/RL 키가 남아 있으면 프론트가 죽은 차트를 되살린다."""
    result = analyst.analyze_now(_stats())
    for key in ("random_forest", "lstm", "rl"):
        assert key not in result


def test_extract_features_arity_and_order():
    feat = MLAnalyst._extract_features(_stats(total=1000, tcp=800, udp=150, icmp=50))
    assert len(feat) == len(FEATURE_NAMES)
    idx = {n: i for i, n in enumerate(FEATURE_NAMES)}
    assert feat[idx["tcp_ratio"]] == pytest.approx(0.8)
    assert feat[idx["udp_ratio"]] == pytest.approx(0.15)
    assert feat[idx["icmp_ratio"]] == pytest.approx(0.05)


def test_extract_features_handles_empty_stats():
    """패킷이 0건일 때 ZeroDivisionError 로 루프가 죽으면 안 된다."""
    feat = MLAnalyst._extract_features({})
    assert len(feat) == len(FEATURE_NAMES)
    assert np.all(np.isfinite(feat))


# ─────────── 4. 합성 데이터의 한계를 회귀로 고정 ───────────

def test_bootstrap_profile_matches_experimental_normal_class():
    """부트스트랩 샘플이 원본 생성기의 NORMAL 클래스와 동일해야
    기존 캐시 모델(iso_forest.pkl / scaler.pkl)과 재현성이 유지된다."""
    from experimental.synthetic_data import generate_training_data
    X, _ = generate_training_data()
    assert np.array_equal(X[:200], _synthetic_normal_profile())


def test_synthetic_classes_are_trivially_separable_by_rules():
    """합성 데이터는 규칙으로 생성됐으므로 규칙으로 거의 완벽히 되풀 수 있다.

    이 테스트가 통과한다는 것은 '이 데이터셋의 F1 점수는 모델 품질의 근거가
    될 수 없다'는 뜻이다. 성능 주장을 되살리려는 시도에 대한 방어선이다.
    """
    from sklearn.metrics import f1_score

    from experimental.synthetic_data import generate_training_data

    X, y = generate_training_data()

    def rule(x):
        pps, bps, tcp, udp, icmp, usrc, udport, apkt = x
        if pps > 4000:
            return 1
        if udport >= 60:
            return 2
        if bps > 4e6 and apkt > 900:
            return 4
        if pps < 35 and bps < 6e4:
            return 5
        if tcp > 0.88 and udport < 5 and pps > 90:
            return 3
        return 0

    pred = np.array([rule(x) for x in X])
    assert f1_score(y, pred, average="macro") > 0.99


def test_model_dir_has_no_orphan_qtable():
    """docs 가 주장했던 q_table.pkl 은 생성된 적이 없다. 되살아나면 알린다."""
    assert not (REPO / "data" / "models" / "q_table.pkl").exists()


def test_feature_columns_match_analyst_feature_names():
    """저장 스키마와 모델 입력 순서가 어긋나면 재학습 데이터가 조용히 망가진다."""
    assert FEATURE_COLUMNS == FEATURE_NAMES


# ─────────── 5. 평가 스크립트 ───────────

def _load_eval_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "eval_ml", REPO / "scripts" / "eval_ml.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_eval_script_reports_insufficiency_instead_of_fake_numbers():
    """데이터가 부족하면 그럴듯한 지표 대신 부족 사유를 내야 한다."""
    ev = _load_eval_module()
    survey = {"verdict": {"real_features": 0, "human_labels": 0,
                          "can_retrain_if": False, "can_evaluate": False,
                          "features_needed": 3000, "labels_needed": 100}}
    result = ev.real_evaluation(survey)
    assert result["status"] == "insufficient_features"
    assert "부족" in result["detail"]

    survey["verdict"].update(real_features=5000, can_retrain_if=True)
    result = ev.real_evaluation(survey)
    assert result["status"] == "insufficient_labels"


def test_eval_script_survey_runs_without_data():
    """DB 가 없거나 비어 있어도 조사는 예외 없이 끝나야 한다."""
    ev = _load_eval_module()
    data = ev.survey()
    assert "verdict" in data and "features" in data
    assert isinstance(data["verdict"]["human_labels"], int)


def test_rule_baseline_covers_every_class():
    """베이스라인이 특정 클래스를 아예 못 내면 비교가 성립하지 않는다."""
    ev = _load_eval_module()
    from experimental.synthetic_data import generate_training_data
    X, y = generate_training_data()
    predicted = {ev.rule_baseline(x) for x in X}
    assert predicted == set(range(6)), f"미출력 클래스 있음: {set(range(6)) - predicted}"


def test_synthetic_control_carries_caveat():
    """합성 수치가 caveat 없이 유출되면 성능 주장으로 오독된다."""
    ev = _load_eval_module()
    s = ev.synthetic_control()
    assert s["caveat"] and "모델 품질이 아니라" in s["caveat"]
    assert s["rule_f1_macro"] > 0.99   # 규칙만으로도 거의 만점


def test_result_before_model_ready_is_not_reported_normal(tmp_path):
    """모델 로드 전 결과가 '정상'으로 읽히면 모델 부재가 정상 판정으로 둔갑한다."""
    s = MLFeatureStore(db_path=str(tmp_path / "f.db"), flush_every=1)
    a = MLAnalyst(FakeSocketIO(), feature_store=s, demo=True)   # 학습 안 함
    try:
        result = a.analyze_now(_stats())
        assert result["model_ready"] is False
        assert result["summary"]["severity"] == "UNKNOWN"
        assert result["summary"]["verdict"] == "모델 준비 안 됨"
        assert "isolation_forest" not in result
    finally:
        s.close()


def test_result_after_model_ready_reports_model_ready(analyst):
    result = analyst.analyze_now(_stats())
    assert result["model_ready"] is True
    assert result["summary"]["severity"] in ("NORMAL", "LOW")


# --------------------------------------------------------------------------- #
#  피처 origin 은 설정이 아니라 실제 트래픽 출처를 따라야 한다
#
#  실측으로 드러난 버그: DEMO_MODE=False 로 띄웠는데 PyShark·Scapy 가 둘 다
#  없어서 PacketAnalyzer 가 조용히 합성 루프로 돌았다. 그런데 origin 은
#  self.demo(=설정)에서 나오고 있어 합성 트래픽 207건이 'real' 로 저장됐다.
#  이대로 3천 건을 모으면 eval_ml.py 가 "실트래픽 재학습 가능"을 선언하고
#  데모 생성기를 학습한다 — 성능 수치가 통째로 거짓이 된다.
# --------------------------------------------------------------------------- #

def _analyst(tmp_path, demo):
    a = MLAnalyst(FakeSocketIO(), demo=demo)
    a.store = MLFeatureStore(str(tmp_path / "f.db"), flush_every=1)
    return a


def test_origin_follows_actual_source_not_config(tmp_path):
    """설정은 실모드인데 실제로는 합성 — 'demo' 로 기록돼야 한다."""
    a = _analyst(tmp_path, demo=False)          # DEMO_MODE=False 로 띄운 상황
    a.feed_traffic({"source_mode": "demo"})     # 그러나 캡처는 합성으로 폴백
    a.store.flush()
    assert a.store.stats()["real"] == 0, "합성 트래픽이 실트래픽으로 저장됐다"
    assert a.store.stats()["demo"] == 1


def test_origin_real_when_capture_is_real(tmp_path):
    a = _analyst(tmp_path, demo=False)
    a.feed_traffic({"source_mode": "real"})
    a.store.flush()
    assert a.store.stats()["real"] == 1


def test_origin_falls_back_to_config_when_unreported(tmp_path):
    """source_mode 를 안 주는 구버전 호출자는 종전대로 설정을 따른다."""
    a = _analyst(tmp_path, demo=True)
    a.feed_traffic({})
    a.store.flush()
    assert a.store.stats()["demo"] == 1


def test_packet_analyzer_reports_demo_when_no_capture_backend(monkeypatch):
    """캡처 백엔드가 없으면 demo=False 로 시작해도 source_mode 는 'demo'."""
    import modules.packet_analyzer as pa

    monkeypatch.setattr(pa, "PYSHARK_AVAILABLE", False)
    monkeypatch.setattr(pa, "SCAPY_AVAILABLE", False)
    an = pa.PacketAnalyzer(FakeSocketIO(), {})
    an.start(demo=False)
    try:
        assert an.source_mode == "demo"
        assert an.get_stats()["source_mode"] == "demo"
    finally:
        an.stop()


def test_packet_analyzer_reports_real_when_backend_present(monkeypatch):
    import modules.packet_analyzer as pa

    monkeypatch.setattr(pa, "PYSHARK_AVAILABLE", True)
    monkeypatch.setattr(pa, "SCAPY_AVAILABLE", False)
    an = pa.PacketAnalyzer(FakeSocketIO(), {})
    monkeypatch.setattr(an, "_capture_pyshark", lambda iface: None)
    an.start(demo=False)
    try:
        assert an.source_mode == "real"
    finally:
        an.stop()
