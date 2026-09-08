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
