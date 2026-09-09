"""Zeek notice.log 연동 — JSON·TSV 파싱, notice 만 승격, 심각도·분류, 로테이션 tail."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.zeek_monitor import ZeekMonitor, ZeekNoticeParser
from modules.soar import SOAREngine
from modules.alert_dedup import extract_rule_id
from modules import mitre_attack as ma

JSON_NOTICE = {"ts": 1788840000.5, "uid": "CabC123", "id.orig_h": "203.0.113.50", "id.orig_p": 45678,
               "id.resp_h": "10.0.0.2", "id.resp_p": 22, "proto": "tcp", "note": "SSH::Password_Guessing",
               "msg": "203.0.113.50 appears to be guessing SSH passwords (seen in 30 connections).",
               "sub": "Sampled servers: 10.0.0.2", "src": "203.0.113.50", "actions": ["Notice::ACTION_LOG"]}
TSV_HEADER = ("#separator \\x09\n#set_separator\t,\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tnote\tmsg\tsub\tsrc\tdst\tp\tactions\n"
              "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tenum\tstring\tstring\taddr\taddr\tport\tset[enum]\n")
TSV_ROW = "1788840001.25\tCx1\t198.51.100.9\t50000\t10.0.0.3\t80\ttcp\tHTTP::SQL_Injection_Attacker\tAn SQL injection attacker was discovered!\t-\t198.51.100.9\t10.0.0.3\t80\tNotice::ACTION_LOG\n"


class Socket:
    def __init__(self): self.events = []
    def emit(self, name, data): self.events.append((name, data))


class Detector:
    def __init__(self): self.alerts = []
    def report_alert(self, *args): self.alerts.append(args)


def test_json_notice_parses_and_maps_severity():
    ev = ZeekNoticeParser().parse(json.dumps(JSON_NOTICE))
    assert ev["note"] == "SSH::Password_Guessing" and ev["severity"] == "HIGH"
    assert ev["src_ip"] == "203.0.113.50" and ev["dst_ip"] == "10.0.0.2" and ev["dst_port"] == 22
    assert ev["category"] == "unsuccessful-user" and ev["timestamp"].startswith("20")


def test_tsv_notice_needs_header_then_parses():
    p = ZeekNoticeParser()
    assert p.parse(TSV_ROW) is None                       # 헤더 전엔 열 이름을 모른다
    for l in TSV_HEADER.splitlines():
        assert p.parse(l) == ("skip", "header")
    ev = p.parse(TSV_ROW)
    assert ev["note"] == "HTTP::SQL_Injection_Attacker" and ev["severity"] == "CRITICAL"
    assert ev["src_ip"] == "198.51.100.9" and ev["dst_port"] == "80" and ev["sub"] == ""


def test_unknown_note_is_medium_and_unmapped():
    ev = ZeekNoticeParser().parse(json.dumps(dict(JSON_NOTICE, note="Custom::Thing")))
    assert ev["severity"] == "MEDIUM" and ev["category"] == ""


def test_notice_enters_detector_with_evidence_and_category():
    sock, det = Socket(), Detector()
    m = ZeekMonitor(sock, {}, det)
    assert m.ingest_line(json.dumps(JSON_NOTICE))
    assert sock.events[0][0] == "zeek_notice" and m.stats["alerts"] == 1
    tt, sev, src, dst, desc, details = det.alerts[0]
    assert tt == "ZEEK_NOTICE" and sev == "HIGH" and src == "203.0.113.50"
    assert desc.startswith("[Zeek SSH::Password_Guessing]")
    assert details["source"] == "zeek" and details["evidence"] == ["zeek_notice"] and details["demo"] is False
    assert ma.ids_category_mappings(details["category"]) == [("TA0006", "T1110")]


def test_garbage_and_headers_do_not_alert():
    m = ZeekMonitor(Socket(), {}, Detector())
    for l in ("", "not json", "[1,2]", "{\"ts\": 1}", "#fields\tts"):
        assert m.ingest_line(l) is None
    # 빈 줄·헤더·note 없는 JSON 은 invalid 가 아니다. 'not json'·'[1,2]' 만 invalid.
    assert m.stats["alerts"] == 0 and m.stats["invalid"] == 2


def test_zeek_notice_is_independent_block_evidence_and_dedup_key():
    alert = {"details": {"source": "zeek", "evidence": ["zeek_notice"],
                         "ip_reputation": {"score": 95, "source": "abuseipdb"}}}
    assert SOAREngine._block_evidence(alert) == ["abuseipdb_90", "zeek_notice"]
    assert extract_rule_id({"source": "zeek", "note": "Scan::Port_Scan"}) == "Scan::Port_Scan"


def test_tail_reads_tsv_header_then_new_rows_and_rotation(tmp_path):
    path = tmp_path / "notice.log"
    path.write_text(TSV_HEADER, encoding="utf-8")
    det = Detector()
    m = ZeekMonitor(Socket(), {"ZEEK_NOTICE_PATH": str(path), "ZEEK_POLL_INTERVAL": "0.05"}, det)
    m.start()
    try:
        time.sleep(0.3)
        with open(path, "a", encoding="utf-8") as f:
            f.write(TSV_ROW)
        time.sleep(0.5)
        assert len(det.alerts) == 1
        # Zeek 의 시간별 회전: 새 파일(새 inode)로 교체되면 헤더부터 다시 읽는다
        os.replace(str(path), str(tmp_path / "notice.old"))
        path.write_text(TSV_HEADER + json.dumps(JSON_NOTICE) + "\n", encoding="utf-8")
        time.sleep(0.6)
        with open(path, "a", encoding="utf-8") as f:
            f.write(TSV_ROW)
        time.sleep(0.5)
        assert len(det.alerts) == 2 and m.stats["invalid"] == 0
    finally:
        m.stop()


def test_disabled_monitor_does_not_start():
    m = ZeekMonitor(Socket(), {"ZEEK_ENABLED": "False"}, Detector())
    m.start()
    assert m.running is False and m.stats["status"] == "disabled"
