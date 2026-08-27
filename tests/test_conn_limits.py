"""동시 연결 상한 — 허니팟 · Syslog TCP (docs/AUDIT.md B-5).

두 모듈 모두 연결마다 스레드를 만들면서 개수 상한이 없었다. 허니팟은
`HONEYPOT_BIND=0.0.0.0` 으로 외부 노출하라고 문서가 권장하는데(실제 침해
포착의 전제), 상한 없이 노출하면 **유인 서비스를 향한 연결 폭주로 대시보드
자신이 스레드 고갈로 죽는다.** 공격자가 마음껏 연결할 수 있는 포트라는 점이
문제의 핵심이다.

실제 소켓으로 연결을 밀어넣어 검증한다 — 세마포어 단위 테스트만으로는
accept 루프와의 결합을 확인할 수 없다.
"""
import socket
import threading
import time

import pytest

from modules.honeypot import Honeypot
from modules.syslog_receiver import SyslogReceiver


class FakeSocketIO:
    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def emit(self, event, data=None, **kwargs):
        with self._lock:
            self.events.append((event, data))


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait(predicate, timeout=5.0, interval=0.02):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(interval)
    return False


# ─────────── 허니팟 ───────────

@pytest.fixture
def honeypot():
    port = _free_port()
    hp = Honeypot(FakeSocketIO(), config={
        "HONEYPOT_ENABLED": "True", "HONEYPOT_BIND": "127.0.0.1",
        "HONEYPOT_PORTS": str(port), "HONEYPOT_MAX_CONNS": 3,
        "HONEYPOT_COOLDOWN": 0,
    })
    hp.start(demo=False)
    if not _wait(lambda: hp.stats.get("ports_open", 0) > 0, timeout=3):
        hp.stop()
        pytest.skip("허니팟 포트 바인딩 실패 (환경 제약)")
    yield hp, port
    hp.stop()
    time.sleep(0.1)


def test_honeypot_max_conns_configured(honeypot):
    hp, _ = honeypot
    assert hp.max_conns == 3
    assert hp.stats["max_conns"] == 3


def test_honeypot_rejects_beyond_limit(honeypot):
    """상한을 넘는 연결은 즉시 끊어야 한다 — 스레드가 무한히 쌓이면 안 된다."""
    hp, port = honeypot
    held = []
    try:
        # 상한(3)만큼 붙잡아 둔다. 핸들러가 3초 recv 대기에 머문다.
        for _ in range(3):
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            held.append(s)
        assert _wait(lambda: hp.stats["active_conns"] == 3), (
            f"활성 연결이 상한에 도달하지 않음: {hp.stats['active_conns']}")

        # 초과분
        for _ in range(5):
            extra = socket.create_connection(("127.0.0.1", port), timeout=2)
            held.append(extra)
        assert _wait(lambda: hp.stats["rejected"] >= 5), (
            f"초과 연결이 거부되지 않음: rejected={hp.stats['rejected']}")
        assert hp.stats["active_conns"] <= 3, (
            f"활성 연결이 상한을 넘음: {hp.stats['active_conns']}")
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass


def test_honeypot_records_rejected_contact(honeypot):
    """상한에 걸려도 '이 IP 가 접촉했다'는 탐지 가치는 지켜야 한다."""
    hp, port = honeypot
    held = []
    try:
        for _ in range(6):
            held.append(socket.create_connection(("127.0.0.1", port), timeout=2))
        assert _wait(lambda: hp.stats["rejected"] >= 1)
        assert _wait(lambda: any(e.get("rejected") for e in hp.events)), (
            "거부된 접촉이 이벤트로 기록되지 않음 — 조용한 누락")
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass


def test_honeypot_slots_released_after_close(honeypot):
    """연결이 끝나면 슬롯이 돌아와야 한다 — 아니면 상한이 영구 소진된다."""
    hp, port = honeypot
    for _ in range(3):
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
    assert _wait(lambda: hp.stats["active_conns"] == 0, timeout=6), (
        f"슬롯이 반환되지 않음: active={hp.stats['active_conns']}")

    # 슬롯이 돌아왔으니 다시 상한만큼 받을 수 있어야 한다
    before = hp.stats["rejected"]
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        assert _wait(lambda: hp.stats["active_conns"] >= 1)
        assert hp.stats["rejected"] == before, "슬롯이 남았는데 거부됨"
    finally:
        s.close()


def test_honeypot_normal_interaction_still_works(honeypot):
    """상한을 넣으면서 정상 유인 동작을 깨면 안 된다."""
    hp, port = honeypot
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        s.sendall(b"root\n")
    finally:
        s.close()
    assert _wait(lambda: hp.stats["total_hits"] >= 1, timeout=6)
    assert any(e["ip"] == "127.0.0.1" for e in hp.events)


# ─────────── Syslog TCP ───────────

@pytest.fixture
def syslog():
    port = _free_port()
    sr = SyslogReceiver(FakeSocketIO(), config={
        "SYSLOG_ENABLED": "True", "SYSLOG_BIND": "127.0.0.1",
        "SYSLOG_PORT": port, "SYSLOG_MAX_CONNS": 2,
    })
    sr.start(demo=False)
    if not _wait(lambda: sr.stats.get("mode") == "real", timeout=3):
        sr.stop()
        pytest.skip("Syslog 포트 바인딩 실패 (환경 제약)")
    yield sr, port
    sr.stop()
    time.sleep(0.1)


def test_syslog_max_conns_configured(syslog):
    sr, _ = syslog
    assert sr.max_conns == 2
    assert sr.stats["max_conns"] == 2


def test_syslog_rejects_beyond_limit(syslog):
    """syslog 연결은 30초 타임아웃으로 오래 살아 상한이 더 중요하다."""
    sr, port = syslog
    held = []
    try:
        for _ in range(2):
            held.append(socket.create_connection(("127.0.0.1", port), timeout=2))
        assert _wait(lambda: sr.stats["active_conns"] == 2), (
            f"활성 연결이 상한에 도달하지 않음: {sr.stats['active_conns']}")

        for _ in range(4):
            held.append(socket.create_connection(("127.0.0.1", port), timeout=2))
        assert _wait(lambda: sr.stats["rejected"] >= 4)
        assert sr.stats["active_conns"] <= 2
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass


def test_syslog_slots_released(syslog):
    sr, port = syslog
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    assert _wait(lambda: sr.stats["active_conns"] == 1)
    s.close()
    assert _wait(lambda: sr.stats["active_conns"] == 0, timeout=6), (
        "연결 종료 후 슬롯이 반환되지 않음")


def test_syslog_normal_message_still_received(syslog):
    """상한을 넣으면서 정상 수신을 깨면 안 된다."""
    sr, port = syslog
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        s.sendall(b"<34>Aug 27 12:00:00 testhost sshd[1]: Failed password "
                  b"for invalid user admin from 203.0.113.99 port 22 ssh2\n")
        assert _wait(lambda: sr.stats["received"] >= 1, timeout=5), (
            "정상 syslog 메시지가 수신되지 않음")
    finally:
        s.close()


# ─────────── 설정 방어 ───────────

@pytest.mark.parametrize("value,expected", [
    (0, 1),            # 0 이면 최소 1
    (-5, 1),
    ("이상한값", 200),   # 파싱 실패 시 기본값
    (None, 200),
])
def test_honeypot_max_conns_sanitised(value, expected):
    hp = Honeypot(FakeSocketIO(), config={
        "HONEYPOT_ENABLED": "False", "HONEYPOT_MAX_CONNS": value})
    assert hp.max_conns == expected


@pytest.mark.parametrize("value,expected", [(0, 1), ("x", 50), (None, 50)])
def test_syslog_max_conns_sanitised(value, expected):
    sr = SyslogReceiver(FakeSocketIO(), config={
        "SYSLOG_ENABLED": "False", "SYSLOG_MAX_CONNS": value})
    assert sr.max_conns == expected
