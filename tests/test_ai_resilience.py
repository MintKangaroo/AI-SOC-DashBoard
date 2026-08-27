"""Claude API 호출 회복력 — 타임아웃·재시도·서킷브레이커 (docs/AUDIT.md B-4).

SDK 기본은 타임아웃 10분 × 재시도 2회 = **최대 30분**이다. `AIAnalyst` 는
단일 워커 큐로 트리아지를 처리하므로 한 번 막히면 그만큼 알림 분석 전체가
정체된다. 챗봇은 SocketIO 핸들러에서 동기 호출이라 요청 스레드도 함께 잡힌다.

핵심 불변식: **AI 가 죽어도 탐지 파이프라인은 계속 흘러야 한다.**
"""
import time

import pytest

import anthropic

from modules.ai_analyst import AIAnalyst


class FakeSocketIO:
    def __init__(self):
        self.events = []

    def emit(self, event, data=None, **kwargs):
        self.events.append((event, data))


class FakeMessages:
    """messages.create 를 흉내내는 스텁. 예외를 주입하거나 응답을 돌려준다."""

    def __init__(self, error=None, text="ok"):
        self.error = error
        self.text = text
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        block = type("Block", (), {"type": "text", "text": self.text})()
        return type("Resp", (), {"content": [block]})()


class FakeClient:
    def __init__(self, error=None, text="ok"):
        self.messages = FakeMessages(error, text)


def _analyst(config=None, error=None, text="ok", available=True):
    a = AIAnalyst(FakeSocketIO(), api_key="", config=config or {})
    a.client = FakeClient(error, text)
    a.available = available
    return a


def _api_error(status=500):
    """APIStatusError 는 response/body 를 요구하므로 최소 형태로 만든다."""
    request = type("Req", (), {"method": "POST", "url": "/v1/messages"})()
    response = type("Resp", (), {"status_code": status, "headers": {},
                                 "request": request})()
    return anthropic.APIStatusError("서버 오류", response=response, body=None)


# ─────────── 타임아웃 · 재시도 설정 ───────────

def test_client_limits_default_to_bounded_values():
    """SDK 기본(10분×3회)을 그대로 쓰면 최대 30분 정체된다."""
    a = AIAnalyst(FakeSocketIO(), api_key="", config={})
    assert a.timeout_seconds == 30.0
    assert a.max_retries == 1
    # 최악 대기 = timeout × (max_retries + 1)
    assert a.timeout_seconds * (a.max_retries + 1) <= 120


def test_client_limits_configurable():
    a = AIAnalyst(FakeSocketIO(), api_key="",
                  config={"AI_TIMEOUT_SECONDS": 12, "AI_MAX_RETRIES": 3})
    assert a.timeout_seconds == 12.0
    assert a.max_retries == 3


def test_invalid_config_falls_back_to_default():
    a = AIAnalyst(FakeSocketIO(), api_key="",
                  config={"AI_TIMEOUT_SECONDS": "이상한값"})
    assert a.timeout_seconds == 30.0


def test_status_exposes_resilience():
    a = _analyst()
    r = a.get_status()["resilience"]
    for key in ("timeout_seconds", "max_retries", "breaker_open",
                "breaker_reopen_in", "fail_streak", "last_error", "calls"):
        assert key in r


# ─────────── 예외 분류 ───────────

@pytest.mark.parametrize("exc,expected", [
    (anthropic.APITimeoutError(request=None), "시간 초과"),
    (anthropic.APIConnectionError(request=None), "네트워크"),
])
def test_error_descriptions_are_specific(exc, expected):
    """하나의 광범위한 except 로는 재시도 가능/불가를 구분할 수 없다."""
    assert expected in AIAnalyst._describe_error(exc)


def test_status_error_reports_code():
    assert "500" in AIAnalyst._describe_error(_api_error(500))


# ─────────── 서킷브레이커 ───────────

def test_breaker_opens_after_consecutive_failures():
    a = _analyst(config={"AI_BREAKER_THRESHOLD": 3, "AI_BREAKER_COOLDOWN": 60},
                 error=_api_error(500))
    for _ in range(2):
        a._call_claude("p", "alert_analysis", 1)
    assert a._breaker_open() is False, "임계 미만인데 차단됨"
    a._call_claude("p", "alert_analysis", 1)
    assert a._breaker_open() is True, "연속 실패 3회 후에도 열리지 않음"


def test_breaker_skips_api_call_and_degrades():
    """차단 중에는 타임아웃을 기다리지 않고 즉시 규칙 기반으로 대체한다."""
    a = _analyst(config={"AI_BREAKER_THRESHOLD": 1, "AI_BREAKER_COOLDOWN": 60},
                 error=_api_error(500))
    a._call_claude("p", "alert_analysis", 1)      # 1회 실패 → 차단
    calls_before = a.client.messages.calls

    result = a._call_claude("p", "alert_analysis", 2)
    assert a.client.messages.calls == calls_before, "차단 중인데 API 를 호출함"
    assert result is not None, "차단 중 결과가 없으면 파이프라인이 멈춘다"
    assert result.get("degraded") is True
    assert a.get_status()["resilience"]["calls"]["skipped_breaker"] == 1


def test_breaker_closes_after_cooldown():
    a = _analyst(config={"AI_BREAKER_THRESHOLD": 1, "AI_BREAKER_COOLDOWN": 0.2},
                 error=_api_error(500))
    a._call_claude("p", "alert_analysis", 1)
    assert a._breaker_open() is True
    time.sleep(0.25)
    assert a._breaker_open() is False, "쿨다운이 지났는데 계속 차단됨"


def test_success_resets_fail_streak():
    a = _analyst(config={"AI_BREAKER_THRESHOLD": 3}, error=_api_error(500))
    a._call_claude("p", "alert_analysis", 1)
    a._call_claude("p", "alert_analysis", 2)
    assert a._fail_streak == 2

    a.client = FakeClient(text='{"is_true_positive": true, "summary": "확인"}')
    a._call_claude("p", "alert_analysis", 3)
    assert a._fail_streak == 0, "성공했는데 실패 카운터가 남음"
    assert a._breaker_open() is False


def test_failure_reason_recorded_in_status():
    a = _analyst(config={"AI_BREAKER_THRESHOLD": 1},
                 error=anthropic.APITimeoutError(request=None))
    a._call_claude("p", "alert_analysis", 1)
    r = a.get_status()["resilience"]
    assert "시간 초과" in r["last_error"]
    assert r["breaker_open"] is True
    assert r["breaker_reopen_in"] > 0


# ─────────── 파이프라인 계속 흐름 ───────────

def test_analysis_returns_result_even_when_api_fails():
    """AI 가 죽어도 트리아지가 결과 없이 멈추면 안 된다."""
    a = _analyst(error=_api_error(500))
    result = a._call_claude("p", "alert_analysis", 1)
    assert result is not None
    assert result.get("degraded") is True
    assert result.get("degraded_reason")


def test_generate_text_returns_none_when_breaker_open():
    """일일 리포트는 실패 시 None 이 계약이다 — 차단 중에도 같아야 한다."""
    a = _analyst(config={"AI_BREAKER_THRESHOLD": 1, "AI_BREAKER_COOLDOWN": 60},
                 error=_api_error(500))
    assert a.generate_text("p") is None
    calls_before = a.client.messages.calls
    assert a.generate_text("p") is None
    assert a.client.messages.calls == calls_before, "차단 중인데 API 를 호출함"


def test_generate_text_succeeds_normally():
    a = _analyst(text="리포트 본문")
    assert a.generate_text("p") == "리포트 본문"
    assert a.get_status()["resilience"]["calls"]["ok"] == 1


def test_chat_falls_back_when_breaker_open():
    """챗봇은 동기 호출이라 요청 스레드를 잡는다 — 차단 중엔 즉시 답해야 한다."""
    a = _analyst(config={"AI_BREAKER_THRESHOLD": 1, "AI_BREAKER_COOLDOWN": 60},
                 error=_api_error(500))
    a._call_claude("p", "alert_analysis", 1)      # 차단 유발
    calls_before = a.client.messages.calls
    reply = a.chat("현재 위협 상황은?")
    assert reply, "차단 중 챗봇이 빈 응답을 냄"
    assert a.client.messages.calls == calls_before


def test_unavailable_analyst_uses_mock_without_client():
    a = AIAnalyst(FakeSocketIO(), api_key="", config={})
    assert a.available is False
    result = a._call_claude("p", "alert_analysis", 1)
    assert result is not None
    assert a.chat("질문")
