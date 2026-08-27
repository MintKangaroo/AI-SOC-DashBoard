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

class _SilentSocketIO:
    def emit(self, *a, **k):
        pass


def _detector(tmp_path, **cfg):
    """ThreatDetector 는 store_path 의 stem 으로 아카이브 *파일*을 만든다.
    ':memory:' 를 주면 작업 디렉터리에 ':memory:_archive.db' 가 남으므로
    반드시 tmp_path 를 쓴다."""
    from modules.threat_detector import ThreatDetector
    return ThreatDetector(_SilentSocketIO(), config=cfg,
                          store_path=str(tmp_path / "alerts.db"))


def test_ddos_threshold_is_applied_from_config(tmp_path):
    td = _detector(tmp_path, DDOS_PACKET_THRESHOLD=777)
    assert td.ddos_pps_threshold == 777, "설정한 임계값이 반영되지 않음"


def test_port_scan_threshold_is_applied_from_config(tmp_path):
    td = _detector(tmp_path, PORT_SCAN_THRESHOLD=5)
    assert td.port_scan_threshold == 5


def test_threshold_defaults_match_previous_behaviour(tmp_path):
    """설정이 없을 때의 기본값은 **실제 동작하던 값**(2000/40)이어야 한다.

    문서값(1000/20)으로 되돌리면 탐지 민감도가 조용히 2배가 된다.
    `Config.DDOS_PACKET_THRESHOLD` 는 로컬 `.env` 가 덮어쓸 수 있으므로
    (실제로 그 환경에 1000 이 들어 있다) 모듈 기본값만 검사한다.
    """
    td = _detector(tmp_path)
    assert td.ddos_pps_threshold == 2000
    assert td.port_scan_threshold == 40


@pytest.mark.parametrize("bad", ["이상한값", None, -1, 0])
def test_threshold_config_is_sanitised(tmp_path, bad):
    td = _detector(tmp_path, DDOS_PACKET_THRESHOLD=bad)
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


# `config.py` 를 거치지 않고 os.getenv 로 직접 읽는 변수들.
# 여기 적힌 것도 .env.example 에는 있어야 한다.
DIRECTLY_READ_ENV = {
    "ANTHROPIC_API_KEY",        # modules/ai_analyst.py
    "AI_MODEL",                 # modules/ai_analyst.py
    "HASH_SCAN_ALLOWED_DIRS",   # api/_common.py
}


def _env_vars_read_by_config():
    """config.py 가 os.getenv 로 읽는 환경변수 전체."""
    text = (REPO / "config.py").read_text(encoding="utf-8")
    return set(re.findall(
        r"(?:getenv|environ\.get)\(\s*[\"\']([A-Z][A-Z0-9_]*)[\"\']", text))


def test_env_example_covers_every_environment_variable():
    """`.env.example` 이 실제로 읽히는 환경변수 전부를 담아야 한다.

    이전에는 26개가 빠져 있었다. 운영자가 `.env.example` 만 보고는
    `SESSION_COOKIE_SECURE`(Tailscale HTTP 에서 로그인이 안 되는 원인)나
    `HASH_SCAN_ALLOWED_DIRS`(경로 탈출 방지 범위) 같은 값이 존재한다는 것
    자체를 알 수 없었다. 이름을 명시적으로 나열하지 않고 소스에서 뽑아
    비교하므로, 새 설정을 추가하면서 문서화를 잊으면 여기서 실패한다.
    """
    documented = _env_example_keys()
    used = _env_vars_read_by_config() | DIRECTLY_READ_ENV
    missing = sorted(used - documented)
    assert missing == [], (
        f".env.example 에 없는 환경변수 {len(missing)}개: {missing}\n"
        f"— 기본값과 한 줄 설명을 붙여 추가할 것.")


def test_env_example_has_no_phantom_variables():
    """반대 방향 — 아무도 읽지 않는 변수를 안내하면 그것도 거짓말이다."""
    documented = _env_example_keys()
    used = _env_vars_read_by_config() | DIRECTLY_READ_ENV
    phantom = sorted(documented - used)
    assert phantom == [], (
        f".env.example 에만 있고 코드가 읽지 않는 변수: {phantom}\n"
        f"— 코드에 연결하거나 .env.example 에서 제거할 것.")


# ─────────── 문서 수치가 실제와 맞는가 (docs/AUDIT.md F-3) ───────────

def test_documented_module_and_panel_counts_match_reality():
    """README·CLAUDE.md 가 주장하는 개수는 셀 수 있고, 그러니 맞아야 한다.

    이전에는 "34개 모듈"(실제 40개), "패널 31개"(실제 33개)처럼 문서가 코드
    성장을 못 따라왔다. 포트폴리오 문서에서 수치가 틀리면 나머지 주장의
    신뢰도까지 깎인다. LOC·테스트 개수는 커밋마다 바뀌므로 여기서 고정하지
    않는다(README 는 '약'·'450+' 로 표기).
    """
    modules = len([p for p in (REPO / "modules").glob("*.py")
                   if p.name != "__init__.py"])
    panels = len(list((REPO / "templates" / "panels").glob("*.html")))

    readme = (REPO / "README.md").read_text(encoding="utf-8")
    claude_md = (REPO / "CLAUDE.md").read_text(encoding="utf-8")

    assert f"{modules}개 모듈" in readme, (
        f"README 의 모듈 수가 실제({modules}개)와 다르다")
    assert f"({panels}개, Jinja include)" in readme, (
        f"README 의 패널 수가 실제({panels}개)와 다르다")
    assert f"(Jinja include, {panels}개)" in claude_md, (
        f"CLAUDE.md 의 패널 수가 실제({panels}개)와 다르다")
