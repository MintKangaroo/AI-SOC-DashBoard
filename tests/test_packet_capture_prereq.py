"""패킷 캡처 전제 — 인터페이스 선택."""


def test_default_interface_picks_default_route_device():
    """WSL 에서 인터페이스 미지정 → PyShark '전체' 모드가 -i - 로 무너져 패킷 0건이던 사건."""
    from modules.packet_analyzer import PacketAnalyzer
    table = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
        "eth0\t00000000\t01A017AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t00A017AC\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0\n"
    )
    assert PacketAnalyzer.default_interface(table) == "eth0"
    assert PacketAnalyzer.default_interface("Iface\tDestination\n") is None
    # 기본 라우트가 DOWN(RTF_UP 미설정)이면 고르지 않는다
    down = table.replace("eth0\t00000000\t01A017AC\t0003", "eth0\t00000000\t01A017AC\t0002")
    assert PacketAnalyzer.default_interface(down) is None


# ---------------------------------------------------------------- #
#  캡처 재활용 — tshark 를 영원히 켜 두지 않는다
# ---------------------------------------------------------------- #
#
# 2026-09-12: 실캡처 tshark 가 10시간 만에 RSS 3.6GB 를 먹어, 9.7GB 짜리 WSL 의
# 가용 메모리가 1.6GB 까지 떨어졌다(전날 커널 OOM 이 여러 프로세스를 죽였다).
# tshark 는 대화·재조립 상태를 캡처가 끝날 때까지 들고 있어 RSS 가 단조 증가한다.
# 그래서 시간·메모리 두 한도로 캡처를 새로 띄운다.
import time

import pytest


def _analyzer(**cfg):
    from modules.packet_analyzer import PacketAnalyzer

    class _Silent:
        def emit(self, *a, **k):
            pass

    return PacketAnalyzer(_Silent(), cfg)


def test_recycle_when_cycle_runs_too_long():
    pa = _analyzer(CAPTURE_RECYCLE_MINUTES=30)
    assert pa.capture_recycle_seconds == 1800
    assert pa._capture_should_recycle(time.time()) is False
    assert pa._capture_should_recycle(time.time() - 1801) is True


def test_recycle_when_capture_processes_grow_too_big(monkeypatch):
    """트래픽이 튀어 시간 한도 전에 부풀면 그때도 새로 띄운다."""
    pa = _analyzer(CAPTURE_RECYCLE_MINUTES=30, CAPTURE_MAX_RSS_MB=700)
    monkeypatch.setattr(pa, "_capture_rss_mb", lambda: 699)
    assert pa._capture_should_recycle(time.time()) is False
    monkeypatch.setattr(pa, "_capture_rss_mb", lambda: 700)
    assert pa._capture_should_recycle(time.time()) is True
    # psutil 이 없어 못 재는 환경에서는 시간 한도만으로 동작해야 한다(예외 금지)
    monkeypatch.setattr(pa, "_capture_rss_mb", lambda: None)
    assert pa._capture_should_recycle(time.time()) is False


def test_close_capture_tolerates_nothing_and_broken_capture():
    """정리는 절대 예외를 밖으로 내보내지 않는다 — 여기서 터지면 캡처가 멈춘다."""
    from modules.packet_analyzer import PacketAnalyzer

    PacketAnalyzer._close_capture(None)

    class Broken:
        _running_processes = None

        def close(self):
            raise RuntimeError("tshark 가 이미 죽었다")

    PacketAnalyzer._close_capture(Broken())


def test_pyshark_still_leaks_the_pipe_we_patch():
    """우리가 덮어쓴 이유가 아직 유효한지 pyshark 원본을 직접 확인한다.

    pyshark 는 `os.pipe()` 로 dumpcap→tshark 를 잇고 **부모 쪽 사본을 안 닫는다**.
    캡처를 재활용하면 그게 캡처당 2개씩 샌다(실측). 그래서 `_FdSafeLiveCapture`
    가 그 메서드를 다시 구현한다 — 남의 내부를 베낀 코드라, 다음 두 가지가
    깨지면 **조용히 원본 동작으로 돌아가는 대신 여기서 시끄럽게 실패**해야 한다.

    - pyshark 가 이 누수를 고쳤다면: 우리 덮어쓰기를 지우면 된다.
    - 내부 이름이 바뀌었다면: `_FdSafeLiveCapture` 를 그 버전에 맞춰야 한다.
    """
    pyshark = pytest.importorskip("pyshark")
    import inspect

    from pyshark.capture import live_capture

    source = inspect.getsource(live_capture.LiveCapture._get_tshark_process)
    assert "os.pipe()" in source, (
        "pyshark 가 파이프 생성 방식을 바꿨다 — 누수가 고쳐졌는지 확인하고 "
        "modules/packet_analyzer._FdSafeLiveCapture 를 지우거나 맞출 것")
    assert "os.close" not in source, (
        "pyshark 가 부모 쪽 파이프를 닫기 시작했다 — 이제 우리 덮어쓰기는 필요 없다. "
        "modules/packet_analyzer._FdSafeLiveCapture 를 지울 것")

    # 덮어쓴 구현이 기대는 내부들
    for name in ("_get_dumpcap_parameters", "_create_stderr_handling_task",
                 "_created_new_process", "_get_tshark_process"):
        assert hasattr(pyshark.LiveCapture, name), f"pyshark 내부 {name} 이 사라졌다"

    from modules.packet_analyzer import _FdSafeLiveCapture
    assert issubclass(_FdSafeLiveCapture, pyshark.LiveCapture)
    assert "os.close" in inspect.getsource(_FdSafeLiveCapture._get_tshark_process)
