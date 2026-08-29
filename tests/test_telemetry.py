"""자기 관측성 (docs/AUDIT.md 3단계 제안 B).

이 감사에서 발견한 문제 대부분은 **관측성이 있었다면 스스로 드러났을 것들**이다 —
B-1 의 0.63초 저장 지연, B-2 의 무성 실패, B-4 의 30분 스톨, B-7 의 34초 쓰기 대기.
`system_health` 는 모듈이 살아 있는지는 답하지만 얼마나 느리고 얼마나 실패하는지는
답하지 못했다.

이 테스트가 지키는 것:

1. **계측이 관측 대상을 망가뜨리지 않는다.** 기록 실패로 탐지 파이프라인이
   멈추거나, 예외가 삼켜져 흐름이 바뀌면 안 된다.
2. **느림과 실패는 다른 문제다.** 한 필드로 뭉뚱그리면 어느 쪽인지 알 수 없다.
3. **프로브가 죽어도 스냅샷이 나온다.** 진단 화면이 진단 대상 때문에 죽으면 안 된다.
"""
import pytest

from modules.telemetry import SLOW_MS, Telemetry


@pytest.fixture
def tel():
    return Telemetry(window=50)


# ─────────────── 기록 ───────────────

def test_timed_records_duration_and_success(tel):
    with tel.timed("x"):
        pass
    point = tel.snapshot()["points"][0]
    assert point["name"] == "x" and point["calls"] == 1 and point["errors"] == 0
    assert point["last_success"] is not None


def test_timed_records_failure_and_reraises(tel):
    """계측이 예외를 삼키면 흐름이 바뀐다 — 그건 계측이 아니라 버그다."""
    with pytest.raises(ValueError):
        with tel.timed("x"):
            raise ValueError("터짐")
    point = tel.snapshot()["points"][0]
    assert point["errors"] == 1 and "터짐" in point["last_error"]
    assert point["last_success"] is None


def test_recording_never_raises(tel):
    """관측 대상을 죽이지 않는다."""
    tel.record("x", float("nan"))
    tel.record("y", "숫자아님")          # 잘못된 입력도 조용히 흘린다
    tel.incr_error("z", error=object())
    assert isinstance(tel.snapshot(), dict)


def test_window_bounds_memory(tel):
    for i in range(500):
        tel.record("x", i)
    point = tel.snapshot()["points"][0]
    assert point["samples"] == 50, "롤링 윈도우가 무한히 자란다"
    assert point["calls"] == 500, "누적 호출 수는 윈도우와 무관하게 유지되어야 한다"


# ─────────────── 느림과 실패의 구분 ───────────────

def test_slow_and_failing_are_separate_signals(tel):
    """느린 것과 실패하는 것은 대응이 다르다."""
    for _ in range(20):
        tel.record("incidents.save", 630.0)          # AUDIT B-1 실측값
    for _ in range(3):
        tel.incr_error("incidents.save", error="too many SQL variables")   # B-2
    point = tel.snapshot()["points"][0]
    assert point["slow"] is True, "p95 630ms 가 임계 200ms 를 넘었는데 안 잡혔다"
    assert point["errors"] == 3
    assert point["last_error"] == "too many SQL variables"


def test_slow_needs_enough_samples(tel):
    """표본 한두 개로 경보를 울리면 늑대소년이 된다 — 실제로 콜드스타트 오탐이 났다."""
    tel.record("incidents.save", 5000.0)      # 기동 직후 첫 저장 한 건
    point = tel.snapshot()["points"][0]
    assert point["slow"] is False
    assert point["warming_up"] is True
    for _ in range(20):
        tel.record("incidents.save", 5000.0)  # 계속 느리면 그때는 잡는다
    point = tel.snapshot()["points"][0]
    assert point["slow"] is True and point["warming_up"] is False


def test_fast_point_is_not_marked_slow(tel):
    for _ in range(20):
        tel.record("incidents.save", 5.0)
    assert tel.snapshot()["points"][0]["slow"] is False


def test_known_hot_paths_have_thresholds():
    """감사에서 문제가 났던 지점은 기본 임계값보다 구체적인 값을 가져야 한다."""
    for name in ("incidents.save", "ai.analyze", "alert_store.search"):
        assert name in SLOW_MS


def test_summary_counts_slow_and_failing(tel):
    for _ in range(10):
        tel.record("incidents.save", 900.0)
    tel.incr_error("other.point", error="boom")
    summary = tel.snapshot()["summary"]
    assert summary["slow"] == 1 and summary["failing"] >= 1


def test_percentiles_are_ordered(tel):
    for value in range(1, 101):
        tel.record("x", value)
    point = tel.snapshot()["points"][0]
    assert point["p50"] <= point["p95"] <= point["max"]


def test_spark_exposes_recent_samples_for_the_chart(tel):
    for i in range(100):
        tel.record("x", i)
    spark = tel.snapshot()["points"][0]["spark"]
    assert 0 < len(spark) <= 40, "스파크라인 표본이 없거나 과하게 많다"
    assert spark[-1] == 99.0, "최근 표본이 끝에 와야 한다"


# ─────────────── 프로브 ───────────────

def test_probe_reports_current_value(tel):
    depth = [0]
    tel.register_probe("q", lambda: depth[0], label="큐", unit="건", warn_above=5)
    assert tel.snapshot()["probes"][0]["value"] == 0
    depth[0] = 9
    probe = tel.snapshot()["probes"][0]
    assert probe["value"] == 9 and probe["warn"] is True


def test_probe_failure_does_not_break_the_snapshot(tel):
    """진단 화면이 진단 대상 때문에 죽으면 안 된다."""
    def exploding():
        raise RuntimeError("모듈 고장")

    tel.register_probe("bad", exploding, label="고장난 프로브")
    tel.record("ok.point", 1.0)
    snapshot = tel.snapshot()
    probe = snapshot["probes"][0]
    assert probe["value"] is None and probe["warn"] is True
    assert "모듈 고장" in probe["error"]
    assert snapshot["points"], "프로브 실패가 계측 지점까지 날려버렸다"


# ─────────────── 실제 배선 ───────────────

def test_hot_paths_are_instrumented_in_the_real_modules():
    """감사에서 문제가 숨었던 경로에 계측이 실제로 붙어 있는지 확인한다."""
    import pathlib
    import re

    repo = pathlib.Path(__file__).resolve().parent.parent
    expected = {
        "modules/incidents.py": "incidents.save",        # B-1
        "modules/ai_analyst.py": "ai.analyze",           # B-4
        "modules/alert_store.py": "alert_store.search",  # B-7
        "modules/threat_detector.py": "detector.add_alert",
        "modules/ip_reputation.py": "ip_reputation.lookup",
    }
    missing = []
    for path, point in expected.items():
        text = (repo / path).read_text(encoding="utf-8")
        if not re.search(rf'telemetry\.timed\(\s*"{re.escape(point)}"', text):
            missing.append(f"{path} → {point}")
    assert missing == [], f"계측이 빠진 경로: {missing}"
