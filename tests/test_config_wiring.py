"""설정 배선 — 선언된 값이 실제로 쓰이는지 (docs/AUDIT.md F-1).

`config.py` 에 선언돼 있지만 아무 데서도 읽히지 않는 변수가 8개 있었다.
그중 `DDOS_PACKET_THRESHOLD`(1000)·`PORT_SCAN_THRESHOLD`(20)는 README 와
CLAUDE.md 가 튜닝 노브로 안내하던 것인데, 실제 코드에는 2000/40 이 박혀
있었다. **운영자가 `.env` 에서 임계값을 조정해도 아무 일이 일어나지 않고,
그 사실을 알 방법이 없었다.**

반대 방향도 있었다 — `siem_correlation` 이 읽는 `SIEM_CORR_*` 5개는
`config.py` 에도 `.env.example` 에도 없어 설정 자체가 불가능했다.

이 테스트는 그 두 방향을 모두 막는다. 새 설정을 추가하면서 배선을 잊으면
여기서 실패한다.
"""
import pathlib
import re

import pytest

# 주의: `config` 를 모듈 레벨에서 import 하지 않는다.
# pytest 는 수집 시점에 모든 테스트 모듈을 import 하는데, 그때 config 가 로드되면
# `Config` 클래스 속성이 **실제 .env 값으로 고정**된다. 이후 앱을 띄우는 다른
# 테스트가 os.environ 을 바꿔도 반영되지 않아, 한 번은 테스트 스위트가 사용자의
# 실제 설정(SOAR_BLOCK_MODE=ufw, 실차단 활성)으로 앱을 기동한 적이 있다.
# 반드시 함수 안에서 import 한다.

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("modules", "api")
SOURCE_FILES = ("app.py", "wiring.py")

# Flask 가 직접 소비하는 설정 — 우리 코드가 읽지 않는 것이 정상이다
FLASK_CONSUMED = {
    "SECRET_KEY", "DEBUG", "SESSION_COOKIE_HTTPONLY", "SESSION_COOKIE_SAMESITE",
    "SESSION_COOKIE_SECURE",
}

# 앱 기동 스크립트(app.py __main__)가 직접 쓰는 값
ENTRYPOINT_CONSUMED = {"HOST", "PORT"}

ALLOWED_UNREAD = FLASK_CONSUMED | ENTRYPOINT_CONSUMED


def _declared_config_keys():
    import config as config_module
    return {name for name in dir(config_module.Config)
            if name.isupper() and not name.startswith("_")}


def _source_text():
    chunks = []
    for sub in SOURCE_DIRS:
        for path in (REPO / sub).rglob("*.py"):
            chunks.append(path.read_text(encoding="utf-8"))
    for name in SOURCE_FILES:
        chunks.append((REPO / name).read_text(encoding="utf-8"))
    return "\n".join(chunks)


def _uppercase_literals(text):
    """소스에 등장하는 대문자 문자열 리터럴 전체.

    '선언됐는데 안 읽힘'을 볼 때 쓴다. `.get("KEY")` 패턴만 찾으면
    `_cfg_int("DDOS_PACKET_THRESHOLD", 2000)` 같은 헬퍼 경유 참조를 놓쳐
    멀쩡히 배선된 설정을 죽었다고 오판한다.
    """
    return set(re.findall(r'["\']([A-Z][A-Z0-9_]{2,})["\']', text))


def _config_access_keys(text):
    """설정 접근 구문에서만 키를 뽑는다.

    '읽는데 선언 안 됨'을 볼 때 쓴다. 대문자 리터럴 전체를 보면 감사
    액션명(SOAR_BLOCK)·위협유형(EDR_THREAT) 같은 설정 아닌 상수까지
    잡히므로, config 객체 접근 형태만 인정한다.
    """
    patterns = (
        r'config[^)\n]{0,24}\.get\(\s*["\']([A-Z][A-Z0-9_]*)["\']',
        r'config\[\s*["\']([A-Z][A-Z0-9_]*)["\']\s*\]',
    )
    found = set()
    for pat in patterns:
        found |= set(re.findall(pat, text))
    return found


def test_every_declared_config_key_is_read():
    """선언만 하고 안 읽는 설정은 '조정해도 아무 일이 없는' 함정이 된다."""
    declared = _declared_config_keys()
    read = _uppercase_literals(_source_text())
    unread = sorted(declared - read - ALLOWED_UNREAD)
    assert unread == [], (
        f"config.py 에 선언됐지만 아무 데서도 읽지 않는 설정: {unread}\n"
        f"— 코드에 연결하거나 config.py 에서 제거할 것. "
        f"Flask/엔트리포인트가 소비하는 값이면 이 파일의 ALLOWED_UNREAD 에 추가.")


def test_every_config_key_read_by_source_is_declared():
    """모듈이 읽는데 config.py 에 없으면 .env 로 설정할 방법이 없다."""
    declared = _declared_config_keys()
    read = _config_access_keys(_source_text())
    missing = sorted(read - declared)
    assert missing == [], (
        f"모듈이 읽지만 config.py 에 선언되지 않은 설정: {missing}\n"
        f"— config.py 에 추가해야 .env 로 조정할 수 있다.")


# ─────────── 탐지 임계값이 실제로 반영되는가 ───────────

def test_ddos_threshold_is_applied_from_config():
    from modules.threat_detector import ThreatDetector

    class S:
        def emit(self, *a, **k):
            pass

    td = ThreatDetector(S(), config={"DDOS_PACKET_THRESHOLD": 777},
                        store_path=":memory:")
    assert td.ddos_pps_threshold == 777, "설정한 임계값이 반영되지 않음"


def test_port_scan_threshold_is_applied_from_config():
    from modules.threat_detector import ThreatDetector

    class S:
        def emit(self, *a, **k):
            pass

    td = ThreatDetector(S(), config={"PORT_SCAN_THRESHOLD": 5},
                        store_path=":memory:")
    assert td.port_scan_threshold == 5


def test_threshold_defaults_match_previous_behaviour():
    """설정이 없을 때의 기본값은 **실제 동작하던 값**(2000/40)이어야 한다.

    문서값(1000/20)으로 되돌리면 탐지 민감도가 조용히 2배가 된다.
    `Config.DDOS_PACKET_THRESHOLD` 는 로컬 `.env` 가 덮어쓸 수 있으므로
    (실제로 그 환경에 1000 이 들어 있다) 모듈 기본값만 검사한다.
    """
    from modules.threat_detector import ThreatDetector

    class S:
        def emit(self, *a, **k):
            pass

    td = ThreatDetector(S(), config={}, store_path=":memory:")
    assert td.ddos_pps_threshold == 2000
    assert td.port_scan_threshold == 40


@pytest.mark.parametrize("bad", ["이상한값", None, -1, 0])
def test_threshold_config_is_sanitised(bad):
    from modules.threat_detector import ThreatDetector

    class S:
        def emit(self, *a, **k):
            pass

    td = ThreatDetector(S(), config={"DDOS_PACKET_THRESHOLD": bad},
                        store_path=":memory:")
    assert td.ddos_pps_threshold >= 1


# ─────────── 나머지 연결 확인 ───────────

def test_max_packets_display_applied():
    from modules.packet_analyzer import PacketAnalyzer

    class S:
        def emit(self, *a, **k):
            pass

    pa = PacketAnalyzer(S(), config={"MAX_PACKETS_DISPLAY": 7})
    assert pa.recent_packets.maxlen == 7


def test_demo_interval_applied():
    from modules.packet_analyzer import PacketAnalyzer

    class S:
        def emit(self, *a, **k):
            pass

    pa = PacketAnalyzer(S(), config={"DEMO_UPDATE_INTERVAL": 0.5})
    assert pa.demo_interval == 0.5


def test_sysmon_channel_applied():
    from modules.sysmon_parser import SysmonParser

    class S:
        def emit(self, *a, **k):
            pass

    sp = SysmonParser(S(), config={"SYSMON_LOG_CHANNEL": "Custom/Channel"})
    assert sp.log_channel == "Custom/Channel"

    default = SysmonParser(S(), config={})
    assert default.log_channel == SysmonParser.LOG_CHANNEL_DEFAULT


def test_siem_correlation_reads_declared_config():
    from modules.siem_correlation import SIEMCorrelator

    class S:
        def emit(self, *a, **k):
            pass

    sc = SIEMCorrelator(S(), config={"SIEM_CORR_WINDOW": 60,
                                     "SIEM_CORR_BRUTE": 2})
    assert sc.window == 60
    assert sc.brute_min == 2


# ─────────── .env.example 동기화 ───────────

def _env_example_keys():
    text = (REPO / ".env.example").read_text(encoding="utf-8")
    return set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]*)=", text, re.M))


def test_env_example_documents_tuning_knobs():
    """운영자가 조정할 값은 .env.example 에 있어야 발견된다."""
    documented = _env_example_keys()
    must_document = {
        "DDOS_PACKET_THRESHOLD", "PORT_SCAN_THRESHOLD",
        "SIEM_CORR_WINDOW", "SIEM_CORR_BRUTE",
        "INCIDENT_AUTO_RESOLVE_DAYS", "DEDUP_WINDOW_SECONDS",
        "AI_TIMEOUT_SECONDS", "HONEYPOT_MAX_CONNS", "CSRF_PROTECTION",
    }
    missing = sorted(must_document - documented)
    assert missing == [], f".env.example 에 없는 튜닝 노브: {missing}"
