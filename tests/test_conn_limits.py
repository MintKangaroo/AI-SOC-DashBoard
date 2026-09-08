"""동시 연결 상한 — Syslog TCP (docs/AUDIT.md B-5).

연결마다 스레드를 만들면서 개수 상한이 없었다. Syslog TCP 를 외부에 노출하면
(원격 수집의 전제) 연결 폭주로 대시보드 자신이 스레드 고갈로 죽는다. 공격자가
마음껏 연결할 수 있는 포트라는 점이 문제의 핵심이다.

실제 소켓으로 연결을 밀어넣어 검증한다 — 세마포어 단위 테스트만으로는
accept 루프와의 결합을 확인할 수 없다.
(허니팟 절은 2026-09-08 기능 제거와 함께 삭제됐다.)
"""
import socket
import threading
import time

import pytest

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

@pytest.mark.parametrize("value,expected", [(0, 1), ("x", 50), (None, 50)])
def test_syslog_max_conns_sanitised(value, expected):
    sr = SyslogReceiver(FakeSocketIO(), config={
        "SYSLOG_ENABLED": "False", "SYSLOG_MAX_CONNS": value})
    assert sr.max_conns == expected
