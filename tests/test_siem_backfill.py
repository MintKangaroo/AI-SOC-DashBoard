"""SIEM 접근 로그 수집 — 첫 적재 유실 수정 및 알림 승격 테스트.

배경: `_collect_loop` 이 첫 적재를 `emit=False` 로 돌리고 `_record_event` 가
그 경우 통계만 올리고 조기 반환해, **과거 로그의 탐지 결과가 전부 폐기**됐다.
실측으로 실제 HIGH 정찰 31건이 유실됐다 (docs/CASE_STUDIES.md 사례 1).

핵심 불변식 두 가지를 지킨다.
1. 과거 로그의 탐지 결과를 버리지 않는다 (MITRE 반영 + 요약 통지).
2. 지난 이벤트로 실시간 부수효과(공격지도·SOAR·알림)를 일으키지 않는다.
   그리고 **어떤 경우에도 SIEM 프로브가 자동차단 플레이북을 열지 않는다.**
"""
import json
import os

import pytest

from modules.access_log_parser import (_CATEGORY_THREAT, _NEVER_PROMOTE_AS,
                                       AccessLogCollector, classify_request)
from modules.alert_dedup import AlertDeduplicator
from modules.threat_detector import ThreatDetector

# 실제 KR 자동매매 로그에서 인용한 정찰 라인 (docs/CASE_STUDIES.md 사례 1~3)
REAL_RECON_LINES = [
    '66.132.172.217 - - [02/Jun/2026 09:04:14] "\\x16\\x03\\x01\\x00\\xee" 400 -',
    '66.132.172.217 - - [02/Jun/2026 09:04:27] "PRI * HTTP/2.0" 505 -',
    '45.33.109.8 - - [04/Jun/2026 11:36:13] "\\x03\\x00\\x00&!\\x00Cookie: mstshash=" 400 -',
    '45.148.10.200 - - [02/Jun/2026 11:10:07] "HELP" 400 -',
    '10.0.14.9 - - [17/Jul/2026 18:56:07] "GET /api/health HTTP/1.1" 200 -',
]


class FakeSocketIO:
    def __init__(self):
        self.events = []

    def emit(self, event, data=None, **kwargs):
        self.events.append((event, data))

    def count(self, name):
        return sum(1 for e, _ in self.events if e == name)


class FakeMitre:
    def __init__(self):
        self.calls = []

    def map_threat(self, threat_type, src_ip=None, dst_ip=None, description=""):
        self.calls.append((threat_type, src_ip, description))


class FakeAttackMap:
    def __init__(self):
        self.calls = []

    def add_attack_ip(self, ip, threat_type, severity):
        self.calls.append((ip, threat_type, severity))


class RecordingSOAR:
    def __init__(self):
        self.siem_events = []
        self.alerts = []

    def handle_siem_event(self, event):
        self.siem_events.append(event)

    def handle_alert(self, alert):
        self.alerts.append(alert)


@pytest.fixture
def logfile(tmp_path):
    p = tmp_path / "server.log"
    p.write_text("\n".join(REAL_RECON_LINES) + "\n", encoding="utf-8")
    return p


def _collector(tmp_path, logfile, **kw):
    sio = kw.pop("socketio", None) or FakeSocketIO()
    col = AccessLogCollector(
        sio, sources=[{"name": "KR 자동매매", "path": str(logfile)}],
        state_path=str(tmp_path / "state.json"), **kw)
    return col, sio


def _detector(tmp_path):
    sio = FakeSocketIO()
    td = ThreatDetector(sio, config={}, store_path=str(tmp_path / "alerts.db"))
    td.dedup = AlertDeduplicator(
        config={"DEDUP_WINDOW_SECONDS": 300, "DEDUP_STORM_THRESHOLD": 100000},
        db_path=str(tmp_path / "dedup.db"))
    return td, sio


# ─────────── 1. 첫 적재가 탐지를 버리지 않는다 ───────────

def test_backfill_no_longer_discards_detections(tmp_path, logfile):
    """회귀 테스트 — 이 값이 0이면 예전 버그가 돌아온 것이다."""
    mitre = FakeMitre()
    col, _ = _collector(tmp_path, logfile, mitre_tracker=mitre)
    col._read_source(col.sources[0], mode="backfill")

    assert col.stats["suspicious_events"] == 3, "의심 이벤트를 놓침"
    assert col.stats["backfilled_suspicious"] == 3
    assert len(mitre.calls) == 3, "backfill 에서 MITRE 매핑이 폐기됨"


def test_backfill_skips_realtime_side_effects(tmp_path, logfile):
    """지난 이벤트로 실시간 지도를 칠하거나 SOAR 를 돌리면 안 된다."""
    amap, soar = FakeAttackMap(), RecordingSOAR()
    td, _ = _detector(tmp_path)
    col, sio = _collector(tmp_path, logfile, mitre_tracker=FakeMitre(),
                          attack_map=amap, threat_detector=td)
    col.soar = soar
    col._read_source(col.sources[0], mode="backfill")

    assert amap.calls == [], "backfill 이 공격 지도를 갱신함"
    assert soar.siem_events == [], "backfill 이 SOAR 를 호출함"
    assert td.stats["total_alerts"] == 0, "backfill 이 알림을 생성함"
    assert sio.count("siem_event") == 0, "backfill 이 실시간 스트림을 폭주시킴"
    try:
        td.dedup.close()
    finally:
        pass


def test_backfill_emits_single_summary(tmp_path, logfile):
    """조용히 버리지 않는다 — 요약 1건으로 알린다."""
    col, sio = _collector(tmp_path, logfile, mitre_tracker=FakeMitre())
    col._emit_backfill_summary([("KR 자동매매", 3)])
    assert sio.count("siem_backfill") == 1
    payload = sio.events[-1][1]
    assert payload["total"] == 3
    assert payload["sources"][0]["name"] == "KR 자동매매"


def test_backfill_summary_silent_when_nothing_found(tmp_path, logfile):
    col, sio = _collector(tmp_path, logfile)
    col._emit_backfill_summary([])
    assert sio.count("siem_backfill") == 0


# ─────────── 2. offset 영속화 — 재시작 시 중복 방지 ───────────

def test_offset_persists_across_restart(tmp_path, logfile):
    """영속화가 없으면 backfill 처리를 켜는 순간 재시작마다 중복이 쏟아진다."""
    col, _ = _collector(tmp_path, logfile, mitre_tracker=FakeMitre())
    col._read_source(col.sources[0], mode="backfill")
    col.sources[0]["backfilled"] = True
    col._save_state()
    assert col.stats["total_events"] == len(REAL_RECON_LINES)

    col2, _ = _collector(tmp_path, logfile, mitre_tracker=FakeMitre())
    assert col2.sources[0]["offset"] == os.path.getsize(logfile)
    assert col2.sources[0]["backfilled"] is True
    col2._read_source(col2.sources[0], mode="live")
    assert col2.stats["total_events"] == 0, "재시작 후 로그를 재처리함"


def test_offset_resets_when_file_rotated(tmp_path, logfile):
    """저장된 offset 이 파일보다 크면 로테이션 → 처음부터 읽는다."""
    state = tmp_path / "state.json"
    state.write_text(json.dumps({str(logfile): {"offset": 10 ** 9, "backfilled": True}}),
                     encoding="utf-8")
    col, _ = _collector(tmp_path, logfile)
    assert col.sources[0]["offset"] == 0


def test_missing_state_file_starts_from_zero(tmp_path, logfile):
    col, _ = _collector(tmp_path, logfile)
    assert col.sources[0]["offset"] == 0
    assert col.sources[0]["backfilled"] is False


def test_corrupt_state_file_does_not_crash(tmp_path, logfile):
    (tmp_path / "state.json").write_text("{ 깨진 JSON", encoding="utf-8")
    col, _ = _collector(tmp_path, logfile)
    assert col.sources[0]["offset"] == 0


def test_save_state_writes_atomically(tmp_path, logfile):
    col, _ = _collector(tmp_path, logfile)
    col.sources[0]["offset"] = 1234
    col._save_state()
    data = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert data[str(logfile)]["offset"] == 1234
    assert not (tmp_path / "state.json.tmp").exists(), "임시 파일이 남음"


# ─────────── 3. 라이브 알림 승격 ───────────

def test_live_promotes_high_probes_to_alerts(tmp_path, logfile):
    """이전에는 SIEM 파일 tail 이벤트가 알림이 된 적이 없었다."""
    td, td_sio = _detector(tmp_path)
    try:
        col, _ = _collector(tmp_path, logfile, mitre_tracker=FakeMitre(),
                            attack_map=FakeAttackMap(), threat_detector=td)
        col._read_source(col.sources[0], mode="live")
        assert td.stats["total_alerts"] == 3
        alerts = list(td.alerts)
        assert {a.threat_type for a in alerts} == {"PORT_SCAN"}
        assert all(a.details["siem_source"] == "KR 자동매매" for a in alerts)
        assert all(a.details["log_timestamp"] for a in alerts)
        assert td_sio.count("new_alert") == 3
    finally:
        td.dedup.close()


def test_normal_request_is_not_promoted(tmp_path, logfile):
    td, _ = _detector(tmp_path)
    try:
        col, _ = _collector(tmp_path, logfile, threat_detector=td)
        col._read_source(col.sources[0], mode="live")
        srcs = {a.src_ip for a in td.alerts}
        assert "10.0.14.9" not in srcs, "정상 내부 요청이 알림이 됨"
    finally:
        td.dedup.close()


def test_promotion_can_be_disabled(tmp_path, logfile):
    td, _ = _detector(tmp_path)
    try:
        col, _ = _collector(tmp_path, logfile, threat_detector=td,
                            promote_alerts=False)
        col._read_source(col.sources[0], mode="live")
        assert td.stats["total_alerts"] == 0
    finally:
        td.dedup.close()


def test_promotion_failure_does_not_stop_collection(tmp_path, logfile):
    """알림 승격이 깨져도 이벤트 수집은 계속되어야 한다."""
    class Broken:
        def report_alert(self, *a, **k):
            raise RuntimeError("고장")

    col, sio = _collector(tmp_path, logfile, threat_detector=Broken())
    col._read_source(col.sources[0], mode="live")
    assert col.stats["total_events"] == len(REAL_RECON_LINES)
    assert sio.count("siem_event") == len(REAL_RECON_LINES)


def test_works_without_threat_detector(tmp_path, logfile):
    """threat_detector 미주입 환경(테스트·데모)에서도 동작해야 한다."""
    col, sio = _collector(tmp_path, logfile, mitre_tracker=FakeMitre())
    col._read_source(col.sources[0], mode="live")
    assert col.stats["suspicious_events"] == 3
    assert sio.count("siem_event") == len(REAL_RECON_LINES)


# ─────────── 4. 안전 불변식: 자동차단 경로를 열지 않는다 ───────────

def test_category_mapping_never_uses_autoblock_threat_types():
    """SOAR 의 PB-BRUTE-BLOCK / PB-HONEYPOT-BLOCK 은 BRUTE_FORCE·HONEYPOT 에만
    반응한다. SIEM 프로브가 그 유형으로 올라가면 스캐너 한 건에 운영 서버
    방화벽이 움직인다."""
    for category, threat_type in _CATEGORY_THREAT.items():
        assert threat_type not in _NEVER_PROMOTE_AS, (
            f"{category} → {threat_type} 은 자동차단 플레이북을 연다")


def test_unknown_category_falls_back_to_anomaly(tmp_path, logfile):
    td, _ = _detector(tmp_path)
    try:
        col, _ = _collector(tmp_path, logfile, threat_detector=td)
        col._promote_to_alert({
            "source": "테스트", "category": "처음 보는 카테고리", "ip": "203.0.113.9",
            "severity": "HIGH", "request": "GET / HTTP/1.1", "status": 200,
            "timestamp": "2026-08-27 12:00:00",
        })
        assert list(td.alerts)[-1].threat_type == "ANOMALY"
    finally:
        td.dedup.close()


def test_promoted_alerts_do_not_reach_autoblock_playbooks(tmp_path, logfile):
    """실제 SOAR 를 붙여 SIEM 유래 알림이 차단 플레이북에 닿지 않음을 확인."""
    from modules.soar import SOAREngine

    td, _ = _detector(tmp_path)
    soar = SOAREngine(FakeSocketIO(),
                      config={"SOAR_BLOCK_MODE": "simulate", "SOAR_AUTO_BLOCK": "True",
                              "SOAR_REQUIRE_CORROBORATION": "False",
                              "SOAR_APPROVAL_REQUIRED": "False"},
                      threat_detector=td)
    soar.blocklist_path = str(tmp_path / "blocklist.txt")
    td.soar = soar
    try:
        col, _ = _collector(tmp_path, logfile, threat_detector=td)
        col._read_source(col.sources[0], mode="live")
        # 알림은 생겼지만
        assert td.stats["total_alerts"] == 3
        # 차단은 한 건도 없어야 한다
        assert soar.blocked_ips == {}, f"SIEM 프로브가 차단을 유발함: {soar.blocked_ips}"
    finally:
        td.dedup.close()


# ─────────── 5. 실제 로그 라인 분류 회귀 고정 ───────────

@pytest.mark.parametrize("line,expected_severity", [
    (REAL_RECON_LINES[0], "HIGH"),   # TLS ClientHello
    (REAL_RECON_LINES[1], "HIGH"),   # HTTP/2 preface
    (REAL_RECON_LINES[2], "HIGH"),   # RDP mstshash
])
def test_real_recon_lines_classified_high(tmp_path, logfile, line, expected_severity):
    col, _ = _collector(tmp_path, logfile)
    ev = col._parse_line(line, "KR 자동매매")
    assert ev is not None and ev["suspicious"]
    assert ev["severity"] == expected_severity


def test_known_miss_help_command_documented():
    """사례 3의 미탐 — 고쳐지면 이 테스트가 실패하며 문서 갱신을 요구한다."""
    suspicious, severity, _ = classify_request("HELP", 400)
    assert suspicious is False, (
        "HELP 미탐이 해소됐다. docs/CASE_STUDIES.md 사례 3을 갱신할 것")
    assert severity == "LOW"
