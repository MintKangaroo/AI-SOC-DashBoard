"""보안 하드닝 회귀 테스트 — docs/AUDIT.md C-1 / C-2 / C-3.

세 항목 모두 감사에서 **실행으로 재현**한 취약점이다. 이 테스트는 그 재현
절차를 그대로 고정해, 수정이 되돌아가면 즉시 실패하게 한다.
"""
import pytest

from modules.patch_manager import PatchManager, check_command


# ══════════════════════════════════════════════════════════════════
#  C-3: 원격 명령 allowlist (blocklist 우회 차단)
# ══════════════════════════════════════════════════════════════════

# 감사에서 blocklist 를 실제로 통과한 명령들 (docs/AUDIT.md C-3)
AUDIT_BYPASSES = [
    "rm -fr /",                       # 옵션 순서
    "rm  -rf /",                      # 공백 추가
    "rm -rf --no-preserve-root /",    # 옵션 추가
    "find / -delete",                 # 다른 명령, 같은 결과
]

SHELL_ESCAPES = [
    "uptime; rm -rf /",
    "uptime && rm -fr /",
    "uptime | sh",
    "uptime `rm -fr /`",
    "uptime $(id)",
    "uptime ${IFS}",
    "df -h > /etc/passwd",
    "df -h < /etc/shadow",
    "uptime\nrm -fr /",
]

# UI 플레이스홀더가 안내하는 정상 용도: "예: uptime · df -h · systemctl status trader"
LEGITIMATE = [
    "uptime", "df -h", "free -m", "ps aux", "uname -a", "hostname",
    "systemctl status trader", "systemctl is-active trader",
    "journalctl -u trader -n 50", "apt list --upgradable",
    "dpkg-query -W -f=${Version} openssh-server".replace("${Version}", "Version"),
]


@pytest.mark.parametrize("cmd", AUDIT_BYPASSES)
def test_audit_bypasses_are_blocked(cmd):
    """감사에서 blocklist 를 통과했던 명령이 이제 막혀야 한다."""
    ok, reason = check_command(cmd)
    assert ok is False, f"C-3 우회가 되살아남: {cmd!r}"
    assert reason


@pytest.mark.parametrize("cmd", SHELL_ESCAPES)
def test_shell_metacharacters_are_blocked(cmd):
    """셸 연결·치환·리다이렉션으로 allowlist 를 우회할 수 없어야 한다."""
    ok, reason = check_command(cmd)
    assert ok is False, f"셸 메타문자 우회 가능: {cmd!r}"


@pytest.mark.parametrize("cmd", LEGITIMATE)
def test_legitimate_diagnostics_still_allowed(cmd):
    """안전장치를 조이면서 정상 용도를 막으면 기능이 죽는다."""
    ok, reason = check_command(cmd)
    assert ok is True, f"정상 명령이 차단됨: {cmd!r} — {reason}"


@pytest.mark.parametrize("cmd", [
    "systemctl restart trader", "systemctl stop trader",
    "systemctl disable trader", "apt install nginx", "apt remove openssh",
])
def test_service_mutating_subcommands_blocked(cmd):
    """운영 중 자동매매 프로세스를 원격에서 내리는 사고를 막는다."""
    ok, _ = check_command(cmd)
    assert ok is False, f"서비스 변경 명령이 통과함: {cmd!r}"


def test_unknown_command_blocked_with_reason():
    ok, reason = check_command("cat /etc/shadow")
    assert ok is False
    assert "허용 목록" in reason


def test_empty_command_blocked():
    assert check_command("")[0] is False
    assert check_command("   ")[0] is False
    assert check_command(None)[0] is False


def test_absolute_path_resolves_to_basename():
    """/bin/rm 처럼 절대경로로 우회할 수 없어야 한다."""
    assert check_command("/bin/rm -fr /")[0] is False
    assert check_command("/usr/bin/uptime")[0] is True


def test_custom_allowlist_is_honored():
    ok, _ = check_command("mytool --status", allowed=("mytool",))
    assert ok is True
    assert check_command("uptime", allowed=("mytool",))[0] is False


def test_run_command_blocks_bypass_end_to_end(tmp_path):
    """PatchManager 를 통해서도 막히는지 — apply 경로 전체 확인."""
    class FakeSIO:
        def emit(self, *a, **k):
            pass

    pm = PatchManager(FakeSIO(), config={"PATCH_APPLY_ENABLED": "True"})
    pm.start(demo=True)
    pm.ansible_adhoc = "/usr/bin/ansible"      # 설치된 것처럼 위장
    job = pm.run_command(command="rm -fr /", mode="apply")
    assert job["status"] == "blocked", f"우회 명령이 실행 경로로 감: {job}"


def test_dry_run_shows_safety_verdict(tmp_path):
    """실행 버튼을 누르기 전에 막힐 것을 미리 알 수 있어야 한다."""
    class FakeSIO:
        def emit(self, *a, **k):
            pass

    pm = PatchManager(FakeSIO(), config={})
    pm.start(demo=True)
    blocked = pm.run_command(command="rm -fr /", mode="check")
    assert "차단" in blocked["log"]
    allowed = pm.run_command(command="uptime", mode="check")
    assert "실행 가능" in allowed["log"]


# ══════════════════════════════════════════════════════════════════
#  C-1 / C-2: CORS 반사 · CSRF
# ══════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """실제 앱을 띄워 CORS/CSRF 를 검증한다.

    앱은 상대 경로("data/…")로 DB 를 만들므로 **임시 디렉터리로 chdir 한 뒤**
    import 한다. 그러지 않으면 테스트가 사용자의 실제 alerts.db·incidents.db 에
    쓴다(실제로 그랬다 — 이 격리는 그 사고를 막기 위한 것이다).

    차단 경로는 simulate, 외부 수집기는 전부 off 로 고정한다.
    """
    import os
    import sys

    workdir = tmp_path_factory.mktemp("app_isolated")
    saved_cwd = os.getcwd()
    saved_env = {k: os.environ.get(k) for k in (
        "AUTH_ENABLED", "SOAR_BLOCK_MODE", "SOAR_AUTO_BLOCK", "SYSLOG_ENABLED",
        "HONEYPOT_ENABLED", "DEMO_MODE", "NTFY_ENABLED", "SNORT_ENABLED",
        "SIEM_ACCESS_LOGS", "AUTH_LOG_PATH", "ANSIBLE_TARGETS",
        "NET_MONITOR_TARGETS", "FUZZ_TARGETS")}

    os.environ.update(
        AUTH_ENABLED="False", SOAR_BLOCK_MODE="simulate", SOAR_AUTO_BLOCK="False",
        SYSLOG_ENABLED="False", HONEYPOT_ENABLED="False", DEMO_MODE="True",
        NTFY_ENABLED="False", SNORT_ENABLED="False",
        SIEM_ACCESS_LOGS="none=/nonexistent/access.log",   # 실로그를 읽지 않는다
        AUTH_LOG_PATH="/nonexistent/auth.log",
        ANSIBLE_TARGETS="", NET_MONITOR_TARGETS="", FUZZ_TARGETS="",
    )
    os.chdir(workdir)
    try:
        sys.modules.pop("app", None)
        import app as app_module
        yield app_module.app.test_client()
    finally:
        sys.modules.pop("app", None)
        os.chdir(saved_cwd)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


EVIL = "https://evil.example"


def test_cors_does_not_reflect_arbitrary_origin(client):
    """C-1 재현: 예전에는 Origin 을 그대로 반사하고 credentials 를 허용했다."""
    r = client.get("/api/soar/status", headers={"Origin": EVIL})
    assert r.headers.get("Access-Control-Allow-Origin") != EVIL, (
        "C-1 재발: 임의 Origin 이 반사됨")
    assert r.headers.get("Access-Control-Allow-Credentials") is None


@pytest.mark.parametrize("headers,label", [
    ({"Origin": EVIL}, "외부 Origin"),
    ({"Referer": EVIL + "/x"}, "외부 Referer"),
    ({}, "출처 헤더 없음"),
])
def test_state_changing_requests_rejected_cross_origin(client, headers, label):
    """C-2 재현: 예전에는 외부 Origin 의 POST 가 그대로 처리됐다."""
    r = client.post("/api/soar/block", json={"ip": "203.0.113.9", "reason": "csrf"},
                    headers=headers)
    assert r.status_code == 403, f"{label} 요청이 통과함"
    assert r.get_json().get("csrf") is True


@pytest.mark.parametrize("headers", [
    {"Origin": "http://localhost"},
    {"Referer": "http://localhost/"},
])
def test_same_origin_requests_still_work(client, headers):
    """보호를 켜면서 정상 UI 동작을 막으면 안 된다."""
    r = client.post("/api/soar/block", json={"ip": "203.0.113.9", "reason": "정상"},
                    headers=headers)
    assert r.status_code != 403


def test_read_requests_are_not_csrf_blocked(client):
    """GET 은 상태를 바꾸지 않는다 — CORS 로 응답 열람만 막으면 된다."""
    assert client.get("/api/soar/status", headers={"Origin": EVIL}).status_code == 200


def test_csrf_guard_covers_all_state_changing_methods(client):
    for method in ("post", "put", "delete"):
        r = getattr(client, method)("/api/watchlist", json={"x": 1},
                                    headers={"Origin": EVIL})
        assert r.status_code == 403, f"{method.upper()} 이 CSRF 가드를 우회함"


def test_login_post_is_csrf_protected(client):
    """로그인 CSRF — 외부 사이트가 폼을 대신 제출하지 못하게."""
    r = client.post("/login", data={"username": "admin", "password": "x"},
                    headers={"Origin": EVIL})
    assert r.status_code == 403


def test_session_cookie_samesite_is_strict(client):
    import app as app_module
    assert app_module.app.config["SESSION_COOKIE_SAMESITE"] == "Strict"
    assert app_module.app.config["SESSION_COOKIE_HTTPONLY"] is True
