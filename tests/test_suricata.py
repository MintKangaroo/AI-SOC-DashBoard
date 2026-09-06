"""Suricata EVE JSON 연동 — 파싱·알림 승격·차단 근거·비-alert 이벤트 처리."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.suricata_monitor import SuricataMonitor, parse_eve_line
from modules.soar import SOAREngine
from modules.alert_dedup import extract_rule_id


ALERT = {
    "timestamp": "2026-09-07T08:12:33.123456+0900", "flow_id": 123456789, "event_type": "alert",
    "src_ip": "203.0.113.50", "src_port": 45678, "dest_ip": "192.168.1.10", "dest_port": 80,
    "proto": "TCP", "app_proto": "http",
    "alert": {"action": "allowed", "gid": 1, "signature_id": 2019401, "rev": 3,
              "signature": "ET WEB_SERVER WordPress Login Bruteforce", "category": "Web Application Attack",
              "severity": 1},
    "http": {"hostname": "shop.example", "url": "/wp-login.php", "http_method": "POST"},
}
FLOW = {"timestamp": "2026-09-07T08:12:34+0900", "event_type": "flow", "src_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2", "proto": "TCP", "flow": {"pkts_toserver": 3}}


class Socket:
    def __init__(self): self.events = []
    def emit(self, name, data): self.events.append((name, data))


class Detector:
    def __init__(self): self.alerts = []
    def report_alert(self, *args): self.alerts.append(args)


def test_parse_alert_event_normalizes_fields():
    ev = parse_eve_line(json.dumps(ALERT))
    assert ev["sid"] == 2019401 and ev["severity"] == 1
    assert ev["src_ip"] == "203.0.113.50" and ev["dst_ip"] == "192.168.1.10" and ev["dst_port"] == 80
    assert ev["category"] == "Web Application Attack"
    assert ev["http_host"] == "shop.example" and ev["http_url"] == "/wp-login.php"


def test_non_alert_events_are_counted_not_promoted():
    """flow/dns/http/stats 를 전부 알림으로 올리면 알림 파이프라인이 트래픽 로그가 된다."""
    assert parse_eve_line(json.dumps(FLOW)) == ("skip", "flow")
    socket, det = Socket(), Detector()
    m = SuricataMonitor(socket, {}, det)
    assert m.ingest_line(json.dumps(FLOW)) is None
    assert m.skipped["flow"] == 1 and det.alerts == [] and socket.events == []


def test_alert_enters_detector_with_context_and_evidence():
    socket, det = Socket(), Detector()
    m = SuricataMonitor(socket, {"SURICATA_ENABLED": "True"}, det)
    ev = m.ingest_line(json.dumps(ALERT))
    assert ev and m.stats["alerts"] == 1
    assert socket.events[0][0] == "suricata_alert"
    threat_type, severity, src, dst, desc, details = det.alerts[0]
    assert threat_type == "SURICATA_ALERT" and severity == "CRITICAL"
    assert src == "203.0.113.50" and dst == "192.168.1.10"
    assert "shop.example/wp-login.php" in desc          # EVE 의 맥락이 설명에 붙는다
    assert details["source"] == "suricata" and details["signature_id"] == 2019401
    assert details["evidence"] == ["suricata_signature"] and details["demo"] is False


def test_severity_mapping_two_and_three():
    det = Detector(); m = SuricataMonitor(Socket(), {}, det)
    for raw, expect in ((2, "HIGH"), (3, "MEDIUM"), (7, "MEDIUM")):
        a = dict(ALERT, alert=dict(ALERT["alert"], severity=raw))
        m.ingest_line(json.dumps(a))
    assert [x[1] for x in det.alerts] == ["HIGH", "MEDIUM", "MEDIUM"]


def test_excluded_sid_loses_block_evidence_but_still_alerts():
    det = Detector()
    m = SuricataMonitor(Socket(), {"SURICATA_BLOCK_EXCLUDED_SIDS": "2019401, 9"}, det)
    m.ingest_line(json.dumps(ALERT))
    details = det.alerts[0][-1]
    assert details["block_excluded"] is True and details["evidence"] == []


def test_garbage_lines_are_invalid_not_crashes():
    m = SuricataMonitor(Socket(), {}, Detector())
    for line in ("", "not json", "[1,2]", json.dumps({"event_type": "alert"}), json.dumps({"event_type": "alert", "alert": {}})):
        assert m.ingest_line(line) is None
    assert m.stats["invalid"] == 5 and m.stats["alerts"] == 0


def test_suricata_signature_counts_as_independent_block_evidence():
    alert = {"details": {"source": "suricata", "evidence": ["suricata_signature"],
                         "ip_reputation": {"score": 95, "source": "abuseipdb"}}}
    assert SOAREngine._block_evidence(alert) == ["abuseipdb_90", "suricata_signature"]


def test_dedup_fingerprint_uses_signature_id():
    """같은 SID 의 반복은 하나로 병합돼야 한다 — 룰 ID 추출이 signature_id 를 알아야 한다."""
    assert extract_rule_id({"source": "suricata", "signature_id": 2019401}) == "2019401"


def test_disabled_monitor_does_not_start_thread():
    m = SuricataMonitor(Socket(), {"SURICATA_ENABLED": "False"}, Detector())
    m.start()
    assert m.running is False and m.stats["status"] == "disabled"


def test_tail_picks_up_new_lines_and_ignores_partial_line(tmp_path):
    import time
    path = tmp_path / "eve.json"
    path.write_text(json.dumps(FLOW) + "\n", encoding="utf-8")   # 기존 내용은 건너뛴다(seek end)
    det = Detector()
    m = SuricataMonitor(Socket(), {"SURICATA_EVE_PATH": str(path), "SURICATA_POLL_INTERVAL": "0.05"}, det)
    m.start()
    try:
        time.sleep(0.2)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ALERT) + "\n")
            f.write(json.dumps(ALERT)[:40])            # 쓰다 만 줄
        time.sleep(0.5)
        assert len(det.alerts) == 1, "완결된 줄 하나만 알림이 되어야 한다"
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ALERT)[40:] + "\n")     # 나머지 절반
        time.sleep(0.5)
        assert len(det.alerts) == 2 and m.stats["invalid"] == 0
    finally:
        m.stop()
