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
        # config 는 import 시점에 .env 를 읽어 클래스 속성을 고정한다.
        # 다른 테스트 모듈이 이미 import 했을 수 있으므로 위 os.environ 을
        # 반영하려면 반드시 다시 로드해야 한다.
        import importlib
        import config as config_mod
        importlib.reload(config_mod)
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
# 내보내기 엔드포인트는 의도적으로 JSON 문서가 아니다.
# CSV 는 표 형식이고, OCSF 는 NDJSON(줄 단위 JSON) — SIEM 수집기가
# 기대하는 형태이고 11만 건을 한 배열로 묶으면 받는 쪽이 통째로 올려야 한다.
NON_JSON_BY_DESIGN = {"/api/alerts/history/export.csv",
                      "/api/alerts/history/export.ocsf.json"}


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


# ─────────────── 알림 이력 검색 범위 (docs/AUDIT.md #13) ───────────────

def test_alerts_history_scope_is_validated(client):
    """알 수 없는 scope 는 SQL 로 흘러들지 않고 400 JSON 으로 거절된다."""
    for path in ("/api/alerts/history", "/api/alerts/history/export.csv"):
        r = client.get(path, query_string={"scope": "'; DROP TABLE alerts--"})
        assert r.status_code == 400
        assert r.is_json and "scope" in r.get_json()["error"]


def test_alerts_history_default_scope_covers_archive(client, app_module):
    """아카이브로 옮긴 알림이 기본 검색에서 사라지지 않고 '보관'으로 표시된다."""
    from datetime import datetime, timedelta

    from modules.threat_detector import Alert

    store = app_module.app.threat_detector.store
    old = Alert("BRUTE_FORCE", "CRITICAL", "203.0.113.7", "10.0.0.5", "아카이브 대상")
    old.timestamp = (datetime.now() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S")
    store.save(old)
    assert store.archive_older_than(90) >= 1

    found = client.get("/api/alerts/history",
                       query_string={"ip": "203.0.113.7"}).get_json()
    assert found["scope"] == "all"
    assert [a["archived"] for a in found["alerts"]] == [True]

    # 활성만 보면 사라지고, 아카이브만 보면 다시 나온다
    assert client.get("/api/alerts/history",
                      query_string={"ip": "203.0.113.7", "scope": "live"}
                      ).get_json()["total"] == 0
    assert client.get("/api/alerts/history",
                      query_string={"ip": "203.0.113.7", "scope": "archive"}
                      ).get_json()["total"] == 1

    # CSV 도 같은 범위를 따르고 archived 열을 포함한다
    csv = client.get("/api/alerts/history/export.csv",
                     query_string={"ip": "203.0.113.7"}).get_data(as_text=True)
    assert "archived" in csv.splitlines()[0]
    assert "203.0.113.7" in csv


# ─────────── 서비스 접근자 (docs/AUDIT.md A-6) ───────────

def test_services_are_accessed_by_name_not_position():
    """위치 언패킹은 순서를 바꾸면 조용히 잘못된 서비스를 바인딩한다.

    예전에는 `_, _, _, hc, _, _ = get_services()` 처럼 셌다. 튜플 순서를 한 칸만
    바꿔도 잡히지 않고, 읽는 쪽에서는 몇 번째가 무엇인지 알 수 없었다.
    실제로 이 전환 과정에서 `dashboard_summary` 가 쓰지도 않는 `hash_checker`
    를 언패킹하고 있던 것이 드러났다 — 위치 언패킹이 가리고 있던 것이다.
    """
    import pathlib
    import re

    repo = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in (repo / "api").glob("*.py"):
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue          # 주석 속 '예전에는 이랬다' 예시는 대상이 아니다
            if re.search(r"=\s*get_services\(\)", line):
                offenders.append(f"{path.name}:{i}")
    assert offenders == [], (
        f"위치 언패킹이 남아 있다: {offenders}\n"
        f"— api._common 의 이름 접근자(threat_detector() 등)를 쓸 것.")


def test_named_accessors_return_the_matching_app_service(app_module):
    """접근자 이름과 app 속성이 실제로 대응하는지 — 오타는 조용히 통과한다."""
    from api import _common

    app = app_module.app
    with app.test_request_context():
        for name in ("packet_analyzer", "threat_detector", "sysmon_parser",
                     "hash_checker", "ai_analyst", "ml_analyst"):
            accessor = getattr(_common, name)
            assert accessor() is getattr(app, name), f"{name} 불일치"


def test_mitre_coverage_endpoint_reports_gaps(client):
    """커버리지 진단이 API 로 나온다 — 세 축이 모두 실려야 한다."""
    d = client.get("/api/mitre/coverage").get_json()
    assert d["summary"]["techniques"] > 0
    assert set(d["summary"]) >= {"with_rule", "validated", "gaps", "seen",
                                 "rule_pct", "validated_pct"}
    # 공백 목록과 매트릭스 셀 상태가 일치해야 한다
    gap_ids = {g["technique_id"] for g in d["gaps"]}
    cells = {t["id"] for tac in d["tactics"] for t in tac["techniques"]
             if t["state"] == "gap"}
    assert gap_ids == cells
    # 실제 구성에서는 매트릭스 밖 기법이 없어야 한다
    assert d["untracked"] == []


def test_telemetry_endpoint_reports_latency_and_probes(client):
    """/api/system/health 가 '살아 있는가'라면 /api/telemetry 는 '얼마나 느린가'다."""
    d = client.get("/api/telemetry").get_json()
    assert set(d) >= {"points", "probes", "summary"}
    assert set(d["summary"]) >= {"points", "slow", "failing", "probe_warnings"}
    # 앱이 뜨면서 알림이 흘렀으므로 계측 지점이 최소 하나는 있어야 한다
    names = {p["name"] for p in d["points"]}
    assert names, "계측 지점이 하나도 없다 — 배선이 끊겼다"
    # 프로브는 모듈을 고치지 않고 등록되므로 항상 존재해야 한다
    assert {p["name"] for p in d["probes"]} >= {"ai.queue_depth", "incidents.dirty"}
    for probe in d["probes"]:
        assert probe.get("error") is None, f"프로브 실패: {probe}"


def test_ocsf_export_returns_ndjson(client):
    """SIEM 수집기가 기대하는 줄 단위 JSON — 11만 건을 한 배열로 묶지 않는다."""
    import json

    r = client.get("/api/alerts/history/export.ocsf.json", query_string={"limit": 5})
    assert r.status_code == 200
    assert r.mimetype == "application/x-ndjson"
    assert r.headers.get("X-OCSF-Class-Uid") == "2004"
    body = r.get_data(as_text=True).strip()
    if body:
        for line in body.split("\n"):
            event = json.loads(line)          # 줄마다 독립적으로 파싱돼야 한다
            assert event["class_uid"] == 2004
            assert event["type_uid"] == event["class_uid"] * 100 + event["activity_id"]


def test_ocsf_export_rejects_bad_scope(client):
    r = client.get("/api/alerts/history/export.ocsf.json",
                   query_string={"scope": "'; DROP TABLE alerts--"})
    assert r.status_code == 400 and r.is_json
