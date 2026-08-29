"""실제 프로세스로 띄워 HTTP 로 검증한다.

나머지 테스트는 전부 Flask `test_client` 로 돈다. 그건 **프로세스도, 소켓도,
백그라운드 스레드 경합도 없고, 작업 디렉터리가 항상 저장소인** 환경이다.
그래서 못 보는 종류가 있다.

실제로 이 테스트가 없어서 놓쳤던 것: **YARA 룰 디렉터리가 없으면 탐지가 통째로
죽는다.** 룰은 `data/yara/` 를 CWD 기준으로 찾는데, 작업 디렉터리가 저장소 밖이면
(systemd 의 WorkingDirectory 가 다른 경우 등) "룰 디렉터리 접근 불가" 한 줄만
남기고 조용히 아무것도 탐지하지 않았다. 테스트 700여 개가 전부 이걸 놓쳤다 —
모두 CWD 가 저장소인 상태에서 돌았기 때문이다.

그래서 여기서는 **빈 임시 디렉터리에서** 앱을 띄운다. 프로젝트 규칙
"모든 모듈은 데모 fallback 필수 — 실제 환경 없이도 실행 가능해야 함"이 진짜인지
확인하는 자리다.

느리다(기동에 10초 안팎). 그래도 CI 에서 돌린다 — 이 종류의 결함은 배포 후에
발견하면 훨씬 비싸다.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

# 프로세스를 띄우므로 느리다. 건너뛰려면 `pytest -m "not live"`.
pytestmark = pytest.mark.live

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STARTUP_TIMEOUT = 90

ENV = {
    "AUTH_ENABLED": "False", "DEMO_MODE": "True", "DEBUG": "False",
    "SOAR_BLOCK_MODE": "simulate", "SOAR_AUTO_BLOCK": "False",
    "PATCH_APPLY_ENABLED": "False", "SYSLOG_ENABLED": "False",
    "HONEYPOT_ENABLED": "False", "SNORT_ENABLED": "False", "NTFY_ENABLED": "False",
    "SIEM_ACCESS_LOGS": "none=/nonexistent/a.log",
    "AUTH_LOG_PATH": "/nonexistent/a.log",
    "ANSIBLE_TARGETS": "", "NET_MONITOR_TARGETS": "", "FUZZ_TARGETS": "",
    "SECRET_KEY": "livetest-only",
    # 감시 주기를 줄여 테스트가 30초를 기다리지 않게 한다
    "YARA_WATCH_INTERVAL": "2",
}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    """**빈 디렉터리에서** 앱을 띄운다 — 저장소 밖에서도 뜨는지가 핵심이다."""
    workdir = tmp_path_factory.mktemp("live")
    (workdir / "watch").mkdir()
    port = _free_port()
    env = {**os.environ, **ENV, "PYTHONPATH": REPO,
           "HOST": "127.0.0.1", "PORT": str(port),
           "YARA_WATCH_DIRS": str(workdir / "watch")}
    log_path = workdir / "server.log"
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.Popen([sys.executable, os.path.join(REPO, "app.py")],
                                cwd=str(workdir), env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(STARTUP_TIMEOUT):
            if proc.poll() is not None:
                pytest.fail(f"기동 중 종료됨:\n{log_path.read_text(encoding='utf-8')[-2000:]}")
            try:
                urllib.request.urlopen(base + "/api/telemetry", timeout=3).read()
                break
            except (urllib.error.URLError, OSError):
                time.sleep(1)
        else:
            pytest.fail(f"기동 시간 초과:\n{log_path.read_text(encoding='utf-8')[-2000:]}")
        yield {"base": base, "workdir": workdir, "log": log_path}
    finally:
        # 프로세스 그룹째 정리한다. pgrep 패턴 매칭은 쓰지 않는다 — 호출한 셸의
        # 명령줄까지 매칭해 자기 자신을 죽이는 사고가 실제로 났다.
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except OSError:
                proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    proc.kill()


def _get(live, path, timeout=60):
    with urllib.request.urlopen(live["base"] + path, timeout=timeout) as r:
        return r.status, r.read()


def _json(live, path, timeout=60):
    return json.loads(_get(live, path, timeout)[1])


# ─────────────── 빈 디렉터리에서 뜨는가 ───────────────

def test_app_starts_outside_the_repository(live):
    """작업 디렉터리가 저장소 밖이어도 떠야 한다."""
    status, body = _get(live, "/")
    assert status == 200 and b"panel-overview" in body


def test_startup_logs_no_errors(live):
    """기동 로그에 ERROR 가 있으면 무언가 조용히 죽은 것이다."""
    text = live["log"].read_text(encoding="utf-8")
    errors = [ln for ln in text.split("\n") if " ERROR " in ln or "Traceback" in ln]
    assert errors == [], "기동 중 오류:\n" + "\n".join(errors[:10])


def test_detection_rules_are_available_from_scratch(live):
    """룰이 없는 환경에서도 탐지가 살아 있어야 한다.

    이게 실제로 깨졌던 지점이다 — YARA 는 룰 디렉터리가 없으면 조용히
    0개로 떴다. Sigma 는 기본 룰을 깔아 살아남았다.
    """
    yara = _json(live, "/api/yara/status")
    assert yara["stats"]["rules_loaded"] > 0, "YARA 룰이 복구되지 않았다"
    sigma = _json(live, "/api/integrations/sigma")
    assert sigma["stats"]["rules_loaded"] > 0, "Sigma 룰이 복구되지 않았다"


def test_all_modules_report_health(live):
    """모듈이 죽은 채로 떠 있으면 헬스 집계가 알려줘야 한다."""
    health = _json(live, "/api/system/health")
    modules = health.get("modules") or health.get("groups") or []
    assert modules, f"헬스 응답이 비었다: {list(health)}"


# ─────────────── 주요 경로가 실제로 응답하는가 ───────────────

@pytest.mark.parametrize("path", [
    "/api/system/health", "/api/telemetry", "/api/alerts/history?limit=5",
    "/api/mitre/coverage", "/api/soar/decisions", "/api/hunts",
    "/api/yara/status", "/api/integrations/sigma", "/api/metrics/soc?days=7",
])
def test_endpoint_responds_over_http(live, path):
    status, body = _get(live, path)
    assert status == 200
    json.loads(body)          # 파싱되지 않으면 JSON 계약이 깨진 것이다


def test_ocsf_export_streams_ndjson(live):
    status, body = _get(live, "/api/alerts/history/export.ocsf.json?limit=5")
    assert status == 200
    text = body.decode("utf-8").strip()
    if text:
        for line in text.split("\n"):
            assert json.loads(line)["class_uid"] == 2004


# ─────────────── 백그라운드 스레드가 실제로 도는가 ───────────────

def test_yara_watch_detects_a_dropped_file(live):
    """감시 스레드는 test_client 로는 절대 검증되지 않는다."""
    sample = live["workdir"] / "watch" / "dropped.php"
    sample.write_text("<?php eval($_POST['c']); ?>", encoding="utf-8")
    for _ in range(30):
        status = _json(live, "/api/yara/status")
        hits = [m for m in status.get("matches", [])
                if m["path"].endswith("dropped.php")]
        if hits:
            assert any(x["rule"] == "SOC_PHP_Webshell" for x in hits[0]["matches"])
            return
        time.sleep(1)
    pytest.fail("감시 디렉터리에 떨어뜨린 웹셸을 시간 내에 탐지하지 못했다")


def test_telemetry_records_real_traffic(live):
    """계측이 실제 요청 경로에 붙어 있는지는 띄워 봐야 안다."""
    for _ in range(3):
        _get(live, "/api/alerts/history?limit=5")
    tel = _json(live, "/api/telemetry")
    names = {p["name"] for p in tel["points"]}
    assert "alert_store.search" in names, f"계측 지점이 비었다: {names}"
    assert tel["summary"]["failing"] == 0, "실패한 계측 지점이 있다"
    assert all(p.get("error") is None for p in tel["probes"])
