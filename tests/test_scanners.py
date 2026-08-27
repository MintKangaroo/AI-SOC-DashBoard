"""
신규 관제 기능 단위 테스트 — 취약점 스캐너 / 웹 퍼저 / Ansible 다중서버
실행: ./venv/bin/pytest tests/test_scanners.py -v

네트워크 요청·실제 ansible 실행 없이 파싱·판정·안전장치 로직만 검증한다.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.vuln_scanner import VulnScanner, _parse_ver, _ver_lt
from modules.web_fuzzer import WebFuzzer, PAYLOADS
from modules.patch_manager import PatchManager


class FakeSocketIO:
    def __init__(self):
        self.emitted = []

    def emit(self, event, data=None, **kwargs):
        self.emitted.append((event, data))


def make_vs(config=None):
    return VulnScanner(FakeSocketIO(), config=config or {})


def make_fuzzer(config=None):
    return WebFuzzer(FakeSocketIO(), config=config or {})


def make_pm(config=None):
    return PatchManager(FakeSocketIO(), config=config or {})


# ══════════════════ vuln_scanner: 버전 비교 ══════════════════

def test_parse_ver():
    assert _parse_ver("8.9p1") == (8, 9, 1)
    assert _parse_ver("1:8.9p1-3ubuntu0.16") == (1, 8, 9, 1)


def test_ver_lt():
    assert _ver_lt((8, 9, 1), (9, 8)) is True
    assert _ver_lt((9, 8), (9, 8)) is False
    assert _ver_lt((1, 21, 0), (1, 21, 0)) is False
    assert _ver_lt((1, 18), (1, 21)) is True


# ══════════════════ vuln_scanner: 배너 휴리스틱 CVE ══════════════════

def test_match_cves_openssh_regresshion():
    vs = make_vs()
    cves = vs._match_cves("OpenSSH 8.9p1 Ubuntu")
    ids = " ".join(c["cve"] for c in cves)
    assert "CVE-2024-6387" in ids


def test_match_cves_nginx_space_format():
    # nmap 은 'nginx 1.18.0' (공백) 형식 → 슬래시/공백 모두 매칭돼야
    vs = make_vs()
    cves = vs._match_cves("http nginx 1.18.0")
    assert any(c["cve"] == "CVE-2021-23017" for c in cves)


def test_match_cves_patched_version_none():
    vs = make_vs()
    # OpenSSH 9.9 → 9.8 미만 아님 → regreSSHion 미매칭
    assert vs._match_cves("OpenSSH 9.9p1") == []


# ══════════════════ vuln_scanner: CVE 중복 제거 ══════════════════

def test_dedup_cves_merges_by_number():
    vs = make_vs()
    dup = [
        {"cve": "CVE-2024-6387 (regreSSHion)", "severity": "high", "desc": "a"},
        {"cve": "CVE-2024-6387", "severity": "medium", "desc": "b"},
        {"cve": "CVE-2023-38408", "severity": "critical", "desc": "c"},
    ]
    out = vs._dedup_cves(dup)
    assert len(out) == 2
    # 최고 심각도 유지 + critical 먼저 정렬
    assert out[0]["cve"] == "CVE-2023-38408"
    merged = [c for c in out if "6387" in c["cve"]][0]
    assert merged["severity"] == "high"


# ══════════════════ vuln_scanner: nmap XML 파싱 ══════════════════

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22">
  <state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.9p1"/>
  <script id="vulners" output="CVE-2023-38408 9.8 https://vulners.com/a CVE-2023-38408 9.8 https://vulners.com/dup CVE-2020-9999 999.0 https://vulners.com/bad"/>
</port>
<port protocol="tcp" portid="3306">
  <state state="closed"/>
  <service name="mysql"/>
</port>
</ports></host></nmaprun>"""


def test_parse_nmap_xml_sanitizes_and_dedups():
    vs = make_vs()
    ports = vs._parse_nmap_xml(_NMAP_XML)
    assert len(ports) == 1                    # closed 포트는 제외
    p = ports[0]
    assert p["port"] == 22
    ids = [c["cve"] for c in p["cves"]]
    # 중복 CVE-2023-38408 은 1개로, CVSS 999(이상값)는 제외
    assert ids.count("CVE-2023-38408") == 1
    assert "CVE-2020-9999" not in ids
    # 배너 휴리스틱으로 regreSSHion 도 보강
    assert "CVE-2024-6387" in " ".join(ids)


def test_parse_nmap_xml_bad_input():
    vs = make_vs()
    assert vs._parse_nmap_xml("<not-xml") is None


# ══════════════════ vuln_scanner: 서비스→패키지, 심각도 ══════════════════

def test_service_to_pkg():
    vs = make_vs()
    assert vs._service_to_pkg({"service": "ssh", "version": "OpenSSH 8.9p1"}) == "openssh-server"
    assert vs._service_to_pkg({"service": "http", "version": "nginx 1.18.0"}) == "nginx"
    assert vs._service_to_pkg({"service": "unknown", "version": ""}) is None


def test_port_severity_rank():
    vs = make_vs()
    assert vs._port_severity([{"severity": "medium"}], [{"severity": "critical"}]) == "critical"
    assert vs._port_severity([{"severity": "high"}], []) == "high"
    assert vs._port_severity([], []) == "info"


# ══════════════════ vuln_scanner: 교차검증 판정 ══════════════════

def test_verdict_vulnerable_when_upgradable():
    vs = make_vs()
    v = vs._verdict_for("openssh-server", "1:8.9p1-3ubuntu0.7",
                        {"openssh-server": "1:8.9p1-3ubuntu0.16"})
    assert v["state"] == "vulnerable"
    assert v["candidate"] == "1:8.9p1-3ubuntu0.16"


def test_verdict_patched_when_backport_and_no_update():
    vs = make_vs()
    v = vs._verdict_for("nginx", "1.18.0-6ubuntu14.16", {})
    assert v["state"] == "patched"


def test_verdict_unknown_when_not_installed():
    vs = make_vs()
    v = vs._verdict_for("redis-server", None, {})
    assert v["state"] == "unknown"


def test_verdict_remote_note_marks_source():
    vs = make_vs()
    v = vs._verdict_for("nginx", "1.18.0-6ubuntu14.16", {}, remote=True)
    assert "원격" in v["note"]


# ══════════════════ vuln_scanner: apt 파싱 ══════════════════

def test_parse_upgradable():
    vs = make_vs()
    out = vs._parse_upgradable(
        "Listing...\n"
        "openssh-server/jammy-security 1:8.9p1-3ubuntu0.18 amd64 [upgradable from: 1:8.9p1-3ubuntu0.16]\n"
        "curl/jammy-security 7.81.0-1ubuntu1.20 amd64 [upgradable from: 7.81.0-1ubuntu1.15]\n"
    )
    assert out["openssh-server"] == "1:8.9p1-3ubuntu0.18"
    assert out["curl"] == "7.81.0-1ubuntu1.20"


def test_parse_remote_apt_marker_split():
    vs = make_vs()
    output = (
        "host | CHANGED | rc=0 >>\n"
        "nginx/jammy 1.18.0-6ubuntu14.17 amd64 [upgradable from: 1.18.0-6ubuntu14.16]\n"
        "===INSTALLED===\n"
        "openssh-server 1:8.9p1-3ubuntu0.16\n"
        "nginx 1.18.0-6ubuntu14.16\n"
    )
    res = vs._parse_remote_apt(output)
    assert res is not None
    upgradable, installed = res
    assert upgradable.get("nginx") == "1.18.0-6ubuntu14.17"
    assert installed.get("openssh-server") == "1:8.9p1-3ubuntu0.16"
    assert installed.get("nginx") == "1.18.0-6ubuntu14.16"


def test_parse_remote_apt_no_marker_returns_none():
    vs = make_vs()
    assert vs._parse_remote_apt("연결 실패 출력") is None


# ══════════════════ vuln_scanner: 인벤토리 / 데모 ══════════════════

def test_write_inventory_local_and_remote():
    vs = make_vs()
    # localhost → local connection
    p1 = vs._write_inventory({"id": "localhost", "addr": "localhost", "conn": "local"})
    txt1 = open(p1).read(); os.remove(p1)
    assert "ansible_connection=local" in txt1
    # user@host → ssh
    p2 = vs._write_inventory({"id": "deploy@10.0.0.11", "addr": "10.0.0.11", "conn": "ssh"})
    txt2 = open(p2).read(); os.remove(p2)
    assert "10.0.0.11" in txt2 and "ansible_user=deploy" in txt2


def test_load_ports_custom():
    vs = make_vs({"VULN_SCAN_PORTS": "22, 80, 443"})
    assert vs.ports == [22, 80, 443]


def test_demo_ports_flagged():
    vs = make_vs()
    ports = vs._demo_ports({"conn": "local", "name": "t", "addr": "127.0.0.1"})
    assert ports and all(p.get("demo") for p in ports)


# ══════════════════ web_fuzzer: 사설 대상 판별 ══════════════════

def test_is_private_host():
    wf = make_fuzzer()
    assert wf._is_private_host("http://127.0.0.1:5055") is True
    assert wf._is_private_host("http://localhost:8080") is True
    assert wf._is_private_host("http://10.0.0.11") is True
    assert wf._is_private_host("http://192.168.1.5") is True
    assert wf._is_private_host("http://100.64.140.27:5055") is True   # Tailscale/CGNAT
    assert wf._is_private_host("http://8.8.8.8") is False             # 공인
    assert wf._is_private_host("http://1.1.1.1:80") is False


# ══════════════════ web_fuzzer: URL 조립 ══════════════════

def test_build_url_appends_query():
    wf = make_fuzzer()
    u = wf._build_url("http://127.0.0.1/x", "q", "a b")
    assert u.startswith("http://127.0.0.1/x?q=")
    assert "%20" in u or "+" in u or "a%20b" in u


def test_build_url_uses_amp_when_query_exists():
    wf = make_fuzzer()
    u = wf._build_url("http://127.0.0.1/x?a=1", "q", "z")
    assert "&q=z" in u


# ══════════════════ web_fuzzer: 응답 분류 ══════════════════

def _target():
    return {"name": "t"}


def test_classify_server_error():
    wf = make_fuzzer()
    r = {"status": 500, "elapsed": 0.01, "text": "", "error": None}
    f = wf._classify(_target(), "/", "q", "overflow", "A" * 10, "u", r, {"elapsed": 0.01})
    assert f["type"] == "server_error" and f["severity"] == "high"


def test_classify_timeout():
    wf = make_fuzzer()
    r = {"status": None, "elapsed": 5, "text": "", "error": "timeout"}
    f = wf._classify(_target(), "/", "q", "empty", "", "u", r, {"elapsed": 0.01})
    assert f["type"] == "timeout" and f["severity"] == "high"


def test_classify_reflection_xss():
    wf = make_fuzzer()
    payload = "<script>alert(1)</script>"
    r = {"status": 200, "elapsed": 0.01, "text": "hi " + payload + " bye", "error": None}
    f = wf._classify(_target(), "/", "q", "xss", payload, "u", r, {"elapsed": 0.01})
    assert f["type"] == "reflection" and f["severity"] == "medium"


def test_classify_latency_spike():
    wf = make_fuzzer()
    r = {"status": 200, "elapsed": 3.0, "text": "ok", "error": None}
    f = wf._classify(_target(), "/", "q", "empty", "", "u", r, {"elapsed": 0.01})
    assert f["type"] == "latency"


def test_classify_ok_returns_none():
    wf = make_fuzzer()
    r = {"status": 200, "elapsed": 0.02, "text": "ok", "error": None}
    assert wf._classify(_target(), "/", "q", "empty", "", "u", r, {"elapsed": 0.02}) is None


# ══════════════════ web_fuzzer: 대상 로드 & 실행 게이트 ══════════════════

def test_load_targets_includes_self_and_netmon():
    wf = make_fuzzer({"PORT": 5055, "NET_MONITOR_TARGETS": "KR=127.0.0.1:5050"})
    names = [t["name"] for t in wf.targets]
    assert "이 SOC 대시보드" in names
    assert any(t["hostport"] == "127.0.0.1:5050" for t in wf.targets)


def test_run_unknown_target():
    wf = make_fuzzer()
    assert wf.run(target_id="nope")["status"] == "error"


def test_run_blocks_public_target():
    wf = make_fuzzer({"FUZZ_TARGETS": "pub=8.8.8.8:80"})
    res = wf.run(target_id="8.8.8.8:80")
    assert res["status"] == "blocked"
    assert wf._fuzzing is False        # 스레드 시작 안 함


def test_run_blocks_post_without_allow_write():
    wf = make_fuzzer()                 # FUZZ_ALLOW_WRITE 기본 False
    res = wf.run(target_id="self", method="POST")
    assert res["status"] == "blocked"
    assert wf._fuzzing is False


def test_payloads_nonempty():
    assert len(PAYLOADS) > 10
    labels = [lbl for lbl, _ in PAYLOADS]
    assert "xss" in labels and "path_traversal" in labels


# ══════════════════ patch_manager: 다중 호스트 인벤토리 ══════════════════

def test_load_hosts_localhost_plus_remote():
    pm = make_pm({"ANSIBLE_TARGETS": "KR 자동매매=deploy@10.0.0.11;USA=deploy@10.0.0.12"})
    ids = [h["id"] for h in pm.hosts]
    assert "localhost" in ids
    assert "deploy@10.0.0.11" in ids and "deploy@10.0.0.12" in ids


def test_hosts_by_id_defaults_localhost():
    pm = make_pm()
    sel = pm._hosts_by_id(None)
    assert len(sel) == 1 and sel[0]["conn"] == "local"


def test_write_inventory_remote_user_host():
    pm = make_pm({"ANSIBLE_TARGETS": "KR=deploy@10.0.0.11"})
    remote = [h for h in pm.hosts if h["conn"] == "ssh"][0]
    path = pm._write_inventory([remote])
    txt = open(path).read(); os.remove(path)
    assert "[targets]" in txt and "ansible_user=deploy" in txt and "10.0.0.11" in txt


# ══════════════════ patch_manager: 안전장치 ══════════════════

def test_run_command_empty_blocked():
    pm = make_pm()
    job = pm.run_command("", host_ids=["localhost"], mode="check")
    assert job["status"] == "blocked"


def test_run_command_check_is_preview_only():
    pm = make_pm()
    job = pm.run_command("uptime", host_ids=["localhost"], mode="check")
    assert job["status"] == "simulated"       # 실행 안 하고 미리보기만
    assert "미리보기" in job["log"]


def test_run_command_apply_blocked_without_gate():
    pm = make_pm({"PATCH_APPLY_ENABLED": "False"})
    job = pm.run_command("uptime", host_ids=["localhost"], mode="apply")
    assert job["status"] == "blocked"
    assert "PATCH_APPLY_ENABLED" in job["result"]


def test_run_command_dangerous_blocked_even_with_gate():
    """파괴적 명령은 PATCH_APPLY_ENABLED=True 여도 차단된다.

    차단 방식이 blocklist → allowlist 로 바뀌면서(docs/AUDIT.md C-3) 사유 문구가
    달라졌다. 문구가 아니라 '차단됐고 사유가 있다'를 검증한다.
    우회 사례 회귀는 tests/test_security_hardening.py 가 따로 고정한다.
    """
    pm = make_pm({"PATCH_APPLY_ENABLED": "True"})
    for danger in ("rm -rf /", "reboot", "mkfs.ext4 /dev/sda", "shutdown now",
                   "rm -fr /", "find / -delete"):
        job = pm.run_command(danger, host_ids=["localhost"], mode="apply")
        assert job["status"] == "blocked", danger
        assert job["result"], f"차단 사유가 비어 있음: {danger}"


def test_run_job_apply_blocked_without_gate():
    pm = make_pm({"PATCH_APPLY_ENABLED": "False"})
    job = pm.run_job(mode="apply", security_only=True, host_ids=["localhost"])
    assert job["status"] == "blocked"


def test_render_playbook_targets_group():
    pm = make_pm()
    content = pm._render_playbook(["openssh-server"], security_only=True)
    assert "hosts: targets" in content
    assert "openssh-server" in content


# ─────────────────── 모듈 헬스 집계 ───────────────────

from modules import system_health


class _FakeApp:
    """system_health.collect() 검증용 최소 app (config + 서비스 속성)."""
    def __init__(self, services, demo=True):
        self.config = {"DEMO_MODE": demo}
        for k, v in services.items():
            setattr(self, k, v)


class _Svc:
    def __init__(self, running=True, stats=None, status=None):
        self.running = running
        self._stats = stats
        self._status = status
    def get_stats(self):
        if self._stats is None:
            raise RuntimeError("no stats")
        return self._stats
    def get_status(self):
        if self._status is None:
            raise RuntimeError("no status")
        return self._status


def test_health_reads_explicit_mode_and_detail():
    app = _FakeApp({
        "edr": _Svc(stats={"mode": "demo", "detections": 5}),
        "net_monitor": _Svc(stats={"mode": "real", "malicious_conns": 2}),
    })
    out = system_health.collect(app)
    mods = {m["key"]: m for m in out["modules"]}
    assert mods["edr"]["mode"] == "demo" and mods["edr"]["detail"] == "탐지 5"
    assert mods["net_monitor"]["mode"] == "real" and mods["net_monitor"]["detail"] == "악성 연결 2"


def test_health_nested_status_stats_authlog():
    # authlog 는 get_stats 없이 get_status()["stats"]["mode"] 로 노출
    app = _FakeApp({"authlog": _Svc(status={"stats": {"mode": "real", "failed": 7}})})
    m = {x["key"]: x for x in system_health.collect(app)["modules"]}["authlog"]
    assert m["mode"] == "real"
    assert m["detail"] == "실패 시도 7"


def test_health_siem_real_when_source_exists():
    app = _FakeApp({
        "siem_collector": _Svc(status={"sources": [{"exists": True}], "stats": {"total_events": 3}}),
    })
    m = {x["key"]: x for x in system_health.collect(app)["modules"]}["siem_collector"]
    assert m["mode"] == "real"


def test_health_down_and_off_and_live():
    app = _FakeApp({
        "packet_analyzer": _Svc(running=False),                       # down
        "notifier": _Svc(status={"active": False}),                   # off
        "mitre_tracker": _Svc(stats={}),                              # live(모드개념 없음)
    })
    m = {x["key"]: x for x in system_health.collect(app)["modules"]}
    assert m["packet_analyzer"]["mode"] == "down" and not m["packet_analyzer"]["running"]
    assert m["notifier"]["mode"] == "off"
    assert m["mitre_tracker"]["mode"] == "live"


def test_health_missing_service_marked_down():
    app = _FakeApp({})  # 아무 서비스도 등록 안 함
    out = system_health.collect(app)
    assert out["summary"]["total"] == len(system_health.SPECS)
    assert all(m["mode"] == "down" for m in out["modules"])
    assert out["summary"]["down"] == len(system_health.SPECS)


# ─────────────────── SOC 운영 지표 ───────────────────

from modules import soc_metrics
from modules.alert_store import AlertStore
from modules.threat_detector import Alert as _MAlert


def test_metrics_aggregate_and_mttr(tmp_path):
    store = AlertStore(str(tmp_path / "m.db"))
    from datetime import datetime
    today = datetime.now().strftime("%Y-%m-%d")
    for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "CRITICAL"]):
        a = _MAlert("DDOS", sev, "9.9.9.9", "1.1.1.1", "x")
        a.timestamp = f"{today} 1{i}:00:00"
        store.save(a)
    # 호스트명 src 는 TOP IP 에서 제외돼야 함
    h = _MAlert("EDR_THREAT", "HIGH", "myhost", "", "x")
    h.timestamp = f"{today} 12:00:00"
    store.save(h)

    incidents = {1: {"created": f"{today} 10:00:00", "timeline": [
        {"ts": f"{today} 10:00:00", "kind": "open", "text": "생성"},
        {"ts": f"{today} 10:20:00", "kind": "status", "text": "상태 변경: OPEN → INVESTIGATING"},
        {"ts": f"{today} 12:00:00", "kind": "status", "text": "상태 변경: INVESTIGATING → RESOLVED"},
    ]}}
    m = soc_metrics.compute(store, incidents,
                            soar_stats={"auto_closed_fp": 3, "escalated_tp": 1}, days=7)
    assert m["kpi"]["total_alerts"] == 5
    assert m["kpi"]["incidents_resolved"] == 1
    assert m["kpi"]["mttr_seconds"] == 2 * 3600   # 10:00 → 12:00
    assert m["kpi"]["mtta_seconds"] == 20 * 60    # 10:00 → 10:20
    assert m["kpi"]["fp_rate"] == 75.0
    ips = [x["ip"] for x in m["top_ips"]]
    assert "9.9.9.9" in ips and "myhost" not in ips
    store.close()


def test_metrics_empty_store_safe():
    m = soc_metrics.compute(None, incidents={}, soar_stats=None, days=14)
    assert m["kpi"]["total_alerts"] == 0
    assert m["kpi"]["mttr"] == "-"
    assert m["kpi"]["fp_rate"] is None


# ─────────────────── 전역 감사 로그 ───────────────────

from modules.audit_log import AuditLog


def test_audit_record_and_search(tmp_path):
    au = AuditLog(str(tmp_path / "audit.db"))
    au.record("kim", "ALERT_ACK", target="알림 #5", detail="확인")
    au.record("lee", "SOAR_BLOCK", target="1.2.3.4", detail="C2")
    au.record("kim", "INCIDENT_STATUS", target="인시던트 #2", detail="RESOLVED")

    rows, total = au.search()
    assert total == 3
    assert rows[0]["id"] > rows[1]["id"]                 # 최신 우선
    assert rows[0]["action_label"] == "인시던트 상태변경"  # 라벨 부가

    _, t_actor = au.search(actor="kim")
    assert t_actor == 2
    _, t_action = au.search(action="SOAR_BLOCK")
    assert t_action == 1
    rows_t, t_text = au.search(text="1.2.3.4")
    assert t_text == 1 and rows_t[0]["actor"] == "lee"
    au.close()


def test_audit_record_never_raises(tmp_path):
    au = AuditLog(str(tmp_path / "a.db"))
    au.close()                       # 닫힌 뒤 기록해도 예외 없이 삼켜야 함
    au.record("x", "ALERT_ACK")      # 조치 흐름을 막지 않기 위함


# ─────────────────── 알림 보존·아카이브 ───────────────────

def test_alert_archive_moves_old(tmp_path):
    store = AlertStore(str(tmp_path / "r.db"))
    from datetime import datetime, timedelta
    old_ts = (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d %H:%M:%S")
    new_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    a_old = _MAlert("DDOS", "HIGH", "1.1.1.1", "2.2.2.2", "오래된")
    a_old.timestamp = old_ts
    a_new = _MAlert("PORT_SCAN", "HIGH", "3.3.3.3", "4.4.4.4", "최근")
    a_new.timestamp = new_ts
    store.save(a_old); store.save(a_new)

    st = store.retention_stats()
    assert st["live"] == 2 and st["archived"] == 0

    moved = store.archive_older_than(90)
    assert moved == 1                       # 100일 전만 이동
    st2 = store.retention_stats()
    assert st2["live"] == 1 and st2["archived"] == 1
    # 활성 테이블엔 최근 알림만 남음 (이력 검색 대상)
    rows, total = store.search()
    assert total == 1 and rows[0]["src_ip"] == "3.3.3.3"
    # 재실행 시 추가 이동 없음
    assert store.archive_older_than(90) == 0
    store.close()


def test_retention_deletes_only_expired_archive(tmp_path):
    store = AlertStore(str(tmp_path / "safe-retention.db"))
    from datetime import datetime, timedelta
    old = _MAlert("DDOS", "HIGH", "1.1.1.1", "2.2.2.2", "old")
    old.timestamp = (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d %H:%M:%S")
    recent = _MAlert("PORT_SCAN", "HIGH", "3.3.3.3", "4.4.4.4", "recent")
    store.save(old); store.save(recent)

    assert store.retention_preview(90, 365)["to_archive"] == 1
    assert store.archive_older_than(90) == 1
    # 아카이브 직후에는 원본 이벤트 시각이 오래돼도 삭제하지 않는다.
    assert store.purge_archive_older_than(365) == 0
    assert store.retention_stats()["live"] == 1
    with store._lock:
        store._conn.execute("UPDATE alerts_archive SET archived_at='2020-01-01 00:00:00'")
        store._conn.commit()
    assert store.retention_preview(90, 365)["archive_to_delete"] == 1
    assert store.purge_archive_older_than(365) == 1
    # 활성 최근 알림은 영구삭제 경로의 영향을 받지 않는다.
    assert store.retention_stats()["live"] == 1
    store.close()


# ─────────────────── 킬체인 상관관계 ───────────────────

from modules import correlation


def test_correlation_builds_killchain():
    labels = {"PORT_SCAN": "포트 스캔", "BRUTE_FORCE": "무차별 대입",
              "MALWARE_BEACON": "C2 통신", "DATA_EXFIL": "데이터 유출"}
    # 한 공격자의 킬체인: 정찰(스캔) → 자격증명(브루트) → C2 → 유출
    base = "2026-07-18 10:0"
    rows = [
        {"id": 1, "threat_type": "PORT_SCAN",      "severity": "MEDIUM",   "src_ip": "8.8.8.8", "dst_ip": "x", "timestamp": base + "0:00"},
        {"id": 2, "threat_type": "BRUTE_FORCE",    "severity": "HIGH",     "src_ip": "8.8.8.8", "dst_ip": "x", "timestamp": base + "2:00"},
        {"id": 3, "threat_type": "MALWARE_BEACON", "severity": "CRITICAL", "src_ip": "8.8.8.8", "dst_ip": "x", "timestamp": base + "5:00"},
        {"id": 4, "threat_type": "DATA_EXFIL",     "severity": "CRITICAL", "src_ip": "8.8.8.8", "dst_ip": "x", "timestamp": base + "8:00"},
        # 다른 IP, 단일 알림 → 캠페인 안 됨(min_alerts=2)
        {"id": 5, "threat_type": "PORT_SCAN",      "severity": "LOW",      "src_ip": "1.1.1.1", "dst_ip": "x", "timestamp": base + "1:00"},
    ]
    camps = correlation.build_campaigns(rows, window_minutes=30, min_alerts=2, labels=labels)
    assert len(camps) == 1
    c = camps[0]
    assert c["src_ip"] == "8.8.8.8"
    assert c["alert_count"] == 4
    assert c["severity"] == "CRITICAL"
    # 킬체인 순서: 정찰 → 자격증명 → C2 → 유출 (전술 order 오름차순)
    tac_order = [s["order"] for s in c["stages"]]
    assert tac_order == sorted(tac_order)
    assert c["stages"][0]["tactic"] == "Reconnaissance"
    assert c["stages"][-1]["tactic"] == "Exfiltration"
    assert c["stage_count"] == 4


def test_correlation_time_window_splits():
    rows = [
        {"id": 1, "threat_type": "PORT_SCAN",   "severity": "HIGH", "src_ip": "9.9.9.9", "dst_ip": "x", "timestamp": "2026-07-18 10:00:00"},
        {"id": 2, "threat_type": "BRUTE_FORCE", "severity": "HIGH", "src_ip": "9.9.9.9", "dst_ip": "x", "timestamp": "2026-07-18 10:10:00"},
        # 2시간 뒤 → 윈도우(30분) 밖 → 별개 세션(단일이라 캠페인 안 됨)
        {"id": 3, "threat_type": "DDOS",        "severity": "HIGH", "src_ip": "9.9.9.9", "dst_ip": "x", "timestamp": "2026-07-18 12:30:00"},
    ]
    camps = correlation.build_campaigns(rows, window_minutes=30, min_alerts=2)
    assert len(camps) == 1 and camps[0]["alert_count"] == 2


# ══════════════════════ Syslog 수신기 ══════════════════════
import time as _time
import socket as _socket
from modules.syslog_receiver import SyslogReceiver, classify_syslog


class _FakeTD:
    def __init__(self):
        self.alerts = []

    def report_alert(self, ttype, sev, src, dst, desc, details=None):
        self.alerts.append((ttype, sev, src, dst, details or {}))


def test_syslog_classify_access_and_keywords():
    # werkzeug 접근 라인 → access 분류 재사용 + 출발지 IP 추출
    susp, sev, cat, ip = classify_syslog(
        '203.0.113.5 - - [06/Jun/2026 20:52:29] "PRI * HTTP/2.0" 505 -')
    assert susp and sev == "HIGH" and ip == "203.0.113.5"
    # 보안 키워드
    susp, sev, cat, ip = classify_syslog(
        "sshd: Failed password for invalid user root from 9.9.9.9 port 22")
    assert susp and cat == "인증 실패/무차별 대입" and ip == "9.9.9.9"
    susp, sev, cat, ip = classify_syslog("app: health check ok")
    assert not susp and sev == "INFO"


def test_syslog_parse_rfc3164_and_5424():
    rx = SyslogReceiver(FakeSocketIO(), {"SYSLOG_ENABLED": "False"})
    # RFC3164
    fac, sev, host, tag, msg = rx._parse(
        "<134>Jul 18 14:00:00 kr-trader sshd: Failed password from 1.2.3.4")
    assert host == "kr-trader" and tag == "sshd" and "Failed password" in msg
    # RFC5424
    fac, sev, host, tag, msg = rx._parse(
        "<134>1 2026-07-18T14:00:00Z usa-trader waf 1234 ID1 - blocked scan from 5.6.7.8")
    assert host == "usa-trader" and tag == "waf" and "blocked scan" in msg


def test_syslog_suspicious_feeds_threat_detector():
    """의심 + 외부 IP → report_alert 로 파이프라인 주입 (매핑된 위협 유형)."""
    td = _FakeTD()
    rx = SyslogReceiver(FakeSocketIO(), {"SYSLOG_ENABLED": "False"}, threat_detector=td)
    rx._handle("<134>Jul 18 14:00:00 kr-trader waf: SQL injection UNION SELECT from 198.51.100.9",
               peer="198.51.100.9", transport="udp")
    assert len(td.alerts) == 1
    assert td.alerts[0][0] == "WEB_ATTACK" and td.alerts[0][2] == "198.51.100.9"
    assert td.alerts[0][4]["source"] == "syslog"


def test_syslog_internal_ip_not_escalated():
    """내부 IP 의심 이벤트는 파이프라인에 올리지 않는다 (오탐 억제)."""
    td = _FakeTD()
    rx = SyslogReceiver(FakeSocketIO(), {"SYSLOG_ENABLED": "False"}, threat_detector=td)
    rx._handle("<134>Jul 18 14:00:00 kr sshd: Failed password from 192.168.1.10",
               peer="192.168.1.10", transport="udp")
    assert td.alerts == []


def test_syslog_udp_tcp_roundtrip():
    """실제 UDP/TCP 소켓 수신 왕복."""
    sio = FakeSocketIO()
    rx = SyslogReceiver(sio, {"SYSLOG_ENABLED": "True", "SYSLOG_BIND": "127.0.0.1",
                              "SYSLOG_PORT": 15517})
    rx.start(demo=False)
    _time.sleep(0.3)
    assert rx.get_stats()["mode"] == "real"
    u = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    u.sendto(b"<134>Jul 18 14:00:00 kr-trader app: hello from 203.0.113.1\n",
             ("127.0.0.1", 15517))
    t = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    t.connect(("127.0.0.1", 15517))
    t.sendall(b"<134>Jul 18 14:00:01 usa-trader app: hi from 203.0.113.2\n")
    t.close()
    _time.sleep(0.5)
    try:
        hosts = {e["host"] for e in rx.get_events()}
        assert "kr-trader" in hosts and "usa-trader" in hosts
        assert rx.get_stats()["received"] >= 2
    finally:
        rx.stop()


# ══════════════════════ 허니팟 ══════════════════════
from modules.honeypot import Honeypot, _sanitize
from modules import honeypot as _hp_mod


def test_honeypot_connect_only_is_high():
    """연결만(입력 없음) → HIGH, 외부 IP 는 파이프라인 주입."""
    td = _FakeTD()
    hp = Honeypot(FakeSocketIO(), {"HONEYPOT_ENABLED": "False", "HONEYPOT_COOLDOWN": 0},
                  threat_detector=td)
    hp._record("203.0.113.10", 2222, "SSH", "", demo=False)
    ev = hp.get_events()[0]
    assert ev["severity"] == "HIGH" and ev["interacted"] is False
    assert len(td.alerts) == 1 and td.alerts[0][0] == "HONEYPOT"


def test_honeypot_interaction_is_critical():
    """자격증명/명령 입력 → CRITICAL."""
    td = _FakeTD()
    hp = Honeypot(FakeSocketIO(), {"HONEYPOT_ENABLED": "False", "HONEYPOT_COOLDOWN": 0},
                  threat_detector=td)
    hp._record("45.155.205.99", 6379, "Redis", "CONFIG SET dir /var/spool/cron/", demo=False)
    ev = hp.get_events()[0]
    assert ev["severity"] == "CRITICAL" and ev["interacted"] is True
    assert td.alerts[0][1] == "CRITICAL" and td.alerts[0][4]["service"] == "Redis"


def test_honeypot_internal_ip_suppressed():
    """내부 IP 접촉은 파이프라인에 올리지 않는다."""
    td = _FakeTD()
    hp = Honeypot(FakeSocketIO(), {"HONEYPOT_ENABLED": "False", "HONEYPOT_COOLDOWN": 0},
                  threat_detector=td)
    hp._record("192.168.1.20", 2222, "SSH", "root:admin", demo=False)
    assert td.alerts == []


def test_honeypot_cooldown_dedups_alerts():
    """동일 IP 반복 접촉은 쿨다운 내 1건만 알림(이벤트는 모두 기록)."""
    td = _FakeTD()
    hp = Honeypot(FakeSocketIO(), {"HONEYPOT_ENABLED": "False", "HONEYPOT_COOLDOWN": 999},
                  threat_detector=td)
    for _ in range(4):
        hp._record("203.0.113.11", 2222, "SSH", "", demo=False)
    assert len(hp.get_events()) == 4
    assert len(td.alerts) == 1


def test_honeypot_real_listener_roundtrip():
    """실제 TCP 유인 리스너 접속 왕복 + 배너 전송 + 입력 수집."""
    _hp_mod.SERVICE_PROFILES[16380] = ("Redis", b"-NOAUTH Authentication required.\r\n")
    hp = Honeypot(FakeSocketIO(), {"HONEYPOT_ENABLED": "True", "HONEYPOT_BIND": "127.0.0.1",
                                   "HONEYPOT_PORTS": "16380", "HONEYPOT_COOLDOWN": 0})
    hp.start(demo=False)
    _time.sleep(0.3)
    try:
        assert hp.get_stats()["mode"] == "real"
        c = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        c.settimeout(3)
        c.connect(("127.0.0.1", 16380))
        assert b"NOAUTH" in c.recv(100)
        c.sendall(b"CONFIG SET dir /tmp\r\n")
        _time.sleep(0.2)
        c.close()
        _time.sleep(0.4)
        ev = hp.get_events()[0]
        assert ev["service"] == "Redis" and ev["interacted"] is True
        assert "CONFIG SET" in ev["payload"]
    finally:
        hp.stop()


def test_honeypot_sanitize_control_chars():
    assert _sanitize("a\x00b\x1fc") == "a\\x00b\\x1fc"


# ══════════════════════ SIEM 상관관계 분석 ══════════════════════
from modules.siem_correlation import SIEMCorrelator


def _mk_corr(td=None, **cfg):
    base = {"SIEM_CORR_MULTIVECTOR": 3, "SIEM_CORR_BRUTE": 5, "SIEM_CORR_DISTRIBUTED": 6}
    base.update(cfg)
    sc = SIEMCorrelator(FakeSocketIO(), base, threat_detector=td)
    sc.start(demo=False)
    return sc


def test_corr_recon_then_intrusion():
    td = _FakeTD()
    sc = _mk_corr(td)
    sc.feed({"src_ip": "203.0.113.9", "threat_type": "PORT_SCAN", "severity": "HIGH"})
    sc.feed({"src_ip": "203.0.113.9", "threat_type": "HONEYPOT", "severity": "CRITICAL"})
    rules = {f["rule"] for f in sc.findings}
    assert "R-RECON-INTRUSION" in rules
    assert any(a[0] == "CORRELATED" for a in td.alerts)


def test_corr_multi_vector():
    sc = _mk_corr()
    for t in ("PORT_SCAN", "BRUTE_FORCE", "WEB_ATTACK"):
        sc.feed({"src_ip": "9.9.9.9", "threat_type": t, "severity": "HIGH"})
    assert any(f["rule"] == "R-MULTI-VECTOR" for f in sc.findings)


def test_corr_sustained_brute():
    sc = _mk_corr()
    for _ in range(5):
        sc.feed({"src_ip": "8.8.8.8", "threat_type": "BRUTE_FORCE", "severity": "HIGH"})
    assert any(f["rule"] == "R-SUSTAINED-BRUTE" for f in sc.findings)


def test_corr_distributed():
    sc = _mk_corr()
    for i in range(6):
        sc.feed({"src_ip": f"1.2.3.{i}", "threat_type": "PORT_SCAN", "severity": "HIGH"})
    dist = [f for f in sc.findings if f["rule"] == "R-DISTRIBUTED"]
    assert dist and dist[0]["count"] >= 6


def test_corr_internal_data_exfil_and_staging():
    td = _FakeTD()
    sc = _mk_corr(td, SIEM_EXFIL_MIN_BYTES=500_000_000)
    sc.feed({"src_ip": "192.168.1.20", "dst_ip": "8.8.8.8",
             "threat_type": "SIGMA_MATCH", "severity": "HIGH"})
    sc.feed({"src_ip": "192.168.1.20", "dst_ip": "8.8.8.8",
             "threat_type": "DATA_EXFIL", "severity": "CRITICAL",
             "details": {"bytes_in_window": 800_000_000}})
    rules = {f["rule"] for f in sc.findings}
    assert "R-INTERNAL-EXFIL" in rules
    assert "R-STAGING-EXFIL" in rules
    correlated = [a for a in td.alerts if a[0] == "CORRELATED"]
    assert correlated and correlated[-1][-1]["evidence"]


def test_corr_cooldown_dedup():
    td = _FakeTD()
    sc = _mk_corr(td, SIEM_CORR_COOLDOWN=999)
    for _ in range(3):
        sc.feed({"src_ip": "7.7.7.7", "threat_type": "PORT_SCAN", "severity": "HIGH"})
        sc.feed({"src_ip": "7.7.7.7", "threat_type": "HONEYPOT", "severity": "CRITICAL"})
    fired = [f for f in sc.findings if f["rule"] == "R-RECON-INTRUSION"]
    assert len(fired) == 1  # 쿨다운으로 1회만
