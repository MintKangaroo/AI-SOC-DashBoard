"""API 에러 처리 — 항상 JSON 으로 답한다 (docs/AUDIT.md A-3).

라우트 93개에 `try/except` 도 `@errorhandler` 도 없었다. 모듈이 예외를 던지면
Flask 기본 500 **HTML** 이 나가고, 프론트의 `.then(r => r.json())` 이 파싱
에러로 죽은 뒤 `.catch(() => {})`(39곳)가 그것을 삼켜 **패널이 조용히 빈 채로
남았다.** 어디가 왜 깨졌는지 화면에도 로그에도 남지 않는 것이 문제였다.

핵심 불변식: **/api/ 는 어떤 실패에도 JSON 을 돌려준다.**
"""
import os
import sys

import pytest


@pytest.fixture(scope="module")
def app_module(tmp_path_factory):
    """실제 앱을 임시 디렉터리에서 띄운다 — 실제 data/ 를 건드리지 않는다."""
    workdir = tmp_path_factory.mktemp("app_errors")
    saved_cwd = os.getcwd()
    keys = ("AUTH_ENABLED", "SOAR_BLOCK_MODE", "SOAR_AUTO_BLOCK", "SYSLOG_ENABLED",
            "HONEYPOT_ENABLED", "DEMO_MODE", "SNORT_ENABLED", "NTFY_ENABLED",
            "SIEM_ACCESS_LOGS", "AUTH_LOG_PATH", "ANSIBLE_TARGETS",
            "NET_MONITOR_TARGETS", "FUZZ_TARGETS", "DEBUG")
    saved_env = {k: os.environ.get(k) for k in keys}
    os.environ.update(
        AUTH_ENABLED="False", SOAR_BLOCK_MODE="simulate", SOAR_AUTO_BLOCK="False",
        SYSLOG_ENABLED="False", HONEYPOT_ENABLED="False", DEMO_MODE="True",
        SNORT_ENABLED="False", NTFY_ENABLED="False", DEBUG="False",
        SIEM_ACCESS_LOGS="none=/nonexistent/access.log",
        AUTH_LOG_PATH="/nonexistent/auth.log",
        ANSIBLE_TARGETS="", NET_MONITOR_TARGETS="", FUZZ_TARGETS="",
    )
    os.chdir(workdir)
    try:
        sys.modules.pop("app", None)
        import app as module
        yield module
    finally:
        sys.modules.pop("app", None)
        os.chdir(saved_cwd)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.fixture
def client(app_module):
    return app_module.app.test_client()


SAME_ORIGIN = {"Origin": "http://localhost"}


# ─────────── HTTP 예외 (404 / 405) ───────────

def test_unknown_api_path_returns_json_404(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404
    assert r.is_json, "API 404 가 HTML 로 나감 — 프론트가 파싱 에러로 죽는다"
    body = r.get_json()
    assert body["status"] == 404
    assert body["path"] == "/api/does-not-exist"
    assert body["error"]


def test_wrong_method_returns_json_405(client):
    r = client.delete("/api/packets", headers=SAME_ORIGIN)
    assert r.status_code == 405
    assert r.is_json
    assert r.get_json()["status"] == 405


def test_non_api_404_stays_html(client):
    """대시보드 페이지 경로까지 JSON 으로 바꾸면 브라우저 UX 가 깨진다."""
    r = client.get("/nope")
    assert r.status_code == 404
    assert not r.is_json


# ─────────── 예상 못한 예외 (500) ───────────

def test_module_exception_returns_json_500(client, app_module, monkeypatch):
    """이것이 A-3 의 본질 — 모듈이 죽어도 프론트는 JSON 을 받아야 한다."""
    def boom(*a, **k):
        raise RuntimeError("모듈 고장")

    monkeypatch.setattr(app_module.app.threat_detector, "get_stats", boom)
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 500
    assert r.is_json, "모듈 예외가 500 HTML 로 나감"
    body = r.get_json()
    assert body["error"]
    assert body["status"] == 500
    assert body["path"] == "/api/dashboard/summary"


def test_500_includes_error_id_for_log_correlation(client, app_module, monkeypatch):
    """식별자가 없으면 '패널이 비었다'는 신고를 서버 로그와 맞출 수 없다."""
    monkeypatch.setattr(app_module.app.threat_detector, "get_stats",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    body = client.get("/api/dashboard/summary").get_json()
    assert body.get("error_id"), "error_id 누락"
    assert len(body["error_id"]) == 8


def test_500_does_not_leak_internals_when_not_debug(client, app_module, monkeypatch):
    """예외 메시지에 경로·내부 구조가 섞일 수 있어 그대로 내보내지 않는다."""
    secret = "내부경로 /home/user/secret/key.pem"
    monkeypatch.setattr(app_module.app.threat_detector, "get_stats",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError(secret)))
    body = client.get("/api/dashboard/summary").get_json()
    assert "detail" not in body
    assert secret not in str(body)


def test_500_includes_detail_when_debug(client, app_module, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "DEBUG", True)
    monkeypatch.setattr(app_module.app.threat_detector, "get_stats",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("진단용")))
    body = client.get("/api/dashboard/summary").get_json()
    assert "진단용" in body.get("detail", "")


def test_error_ids_are_unique_per_request(client, app_module, monkeypatch):
    monkeypatch.setattr(app_module.app.threat_detector, "get_stats",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    ids = {client.get("/api/dashboard/summary").get_json()["error_id"]
           for _ in range(3)}
    assert len(ids) == 3, "요청마다 다른 식별자여야 로그 대조가 된다"


# ─────────── 기존 동작 보존 ───────────

def test_successful_requests_unaffected(client):
    for path in ("/api/alerts", "/api/soar/status", "/api/ml/status",
                 "/api/system/health", "/api/dedup/status"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} 가 깨짐"
        assert r.is_json


def test_deliberate_400_still_works(client):
    """라우트가 의도적으로 내는 4xx 를 핸들러가 삼키면 안 된다."""
    r = client.post("/api/soar/block", json={}, headers=SAME_ORIGIN)
    assert r.status_code == 400
    assert "ip" in r.get_json()["error"]


def test_csrf_403_not_swallowed(client):
    """CSRF 가드의 403 은 그대로 유지되어야 한다."""
    r = client.post("/api/soar/block", json={"ip": "203.0.113.9"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert r.get_json().get("csrf") is True


# 성공 응답이 의도적으로 JSON 이 아닌 엔드포인트 (파일 다운로드)
NON_JSON_BY_DESIGN = {"/api/alerts/history/export.csv"}


def test_every_get_endpoint_returns_json(client, app_module):
    """인자 없는 GET 엔드포인트 전수 — 파일 내려받기 외에는 JSON 이어야 한다."""
    offenders = []
    for rule in app_module.app.url_map.iter_rules():
        path = str(rule)
        if not path.startswith("/api/") or "<" in path:
            continue
        if "GET" not in (rule.methods or set()):
            continue
        if path in NON_JSON_BY_DESIGN:
            continue
        r = client.get(path)
        if not r.is_json:
            offenders.append((path, r.status_code, r.headers.get("Content-Type")))
    assert offenders == [], f"JSON 이 아닌 응답: {offenders}"


def test_csv_export_errors_still_return_json(client, app_module, monkeypatch):
    """CSV 내보내기는 성공 시 CSV 지만, 실패하면 JSON 이어야 한다.

    실패까지 CSV/HTML 로 나가면 프론트가 오류를 인지하지 못한다.
    """
    monkeypatch.setattr(app_module.app.threat_detector, "search_alerts",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("검색 고장")))
    r = client.get("/api/alerts/history/export.csv")
    assert r.status_code == 500
    assert r.is_json, "CSV 내보내기 실패가 JSON 이 아님"
    assert r.get_json().get("error_id")
