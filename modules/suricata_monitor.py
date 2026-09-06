"""Suricata EVE JSON(eve.json) 을 SOC 알림 파이프라인으로 전달한다.

Snort 연동(snort_monitor)과 같은 자리다 — IDS 는 탐지 근거 하나를 줄 뿐 차단을
직접 하지 않는다. 차단은 SOAR 의 복수 근거·고신뢰·승인 게이트가 따로 결정한다.

왜 Suricata 를 따로 두나: Snort 는 fast-alert 한 줄에 SID·메시지·주소만 남긴다.
Suricata 의 EVE 는 이벤트마다 JSON 이라 **분류(category)·앱 프로토콜·HTTP 호스트/
URL·DNS 질의** 같은 맥락이 함께 온다. 분석가가 "SID 2100498 이 뭐지" 대신
"이 호스트의 /wp-login.php 로 온 요청" 을 바로 본다. 룰셋도 ET Open 이 그대로 붙는다.

EVE 파일에는 alert 외에 flow·dns·http·stats·fileinfo 이벤트가 훨씬 많이 섞여
있다. 여기서는 **alert 만** 알림으로 올리고 나머지는 종류별로 세기만 한다 —
flow 를 전부 알림으로 올리면 알림 파이프라인이 곧 트래픽 로그가 된다.
"""
import json
import os
import subprocess
import threading
import time
from collections import Counter, deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)

# Suricata alert.severity: 1 이 가장 높다(Snort priority 와 같은 방향)
_SEVERITY = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}


def parse_eve_line(line):
    """eve.json 한 줄을 정규화한다.

    반환: alert 이벤트면 dict, alert 가 아닌 유효 이벤트면 ("skip", event_type),
    JSON 이 아니거나 필수 필드가 없으면 None.
    """
    line = (line or "").strip()
    if not line:
        return None
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    if not isinstance(ev, dict):
        return None
    etype = ev.get("event_type")
    if etype != "alert":
        return ("skip", str(etype or "unknown"))
    alert = ev.get("alert") or {}
    if not isinstance(alert, dict) or alert.get("signature_id") is None:
        return None

    def _int(v, default=None):
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    http = ev.get("http") if isinstance(ev.get("http"), dict) else {}
    dns = ev.get("dns") if isinstance(ev.get("dns"), dict) else {}
    severity = _int(alert.get("severity"), 3)
    return {
        "timestamp": str(ev.get("timestamp") or ""),
        "flow_id": ev.get("flow_id"),
        "sid": _int(alert.get("signature_id")),
        "gid": _int(alert.get("gid"), 1),
        "rev": _int(alert.get("rev"), 0),
        "signature": str(alert.get("signature") or ""),
        "category": str(alert.get("category") or ""),
        "severity": severity,
        "action": str(alert.get("action") or ""),
        "src_ip": ev.get("src_ip"), "src_port": _int(ev.get("src_port")),
        "dst_ip": ev.get("dest_ip"), "dst_port": _int(ev.get("dest_port")),
        "protocol": str(ev.get("proto") or ""),
        "app_proto": str(ev.get("app_proto") or ""),
        "http_host": str(http.get("hostname") or "") or None,
        "http_url": str(http.get("url") or "")[:200] or None,
        "dns_query": str((dns.get("rrname") or dns.get("query") or "")) or None,
    }


class SuricataMonitor:
    def __init__(self, socketio, config=None, threat_detector=None):
        config = config or {}
        self.socketio = socketio
        self.threat_detector = threat_detector
        self.enabled = str(config.get("SURICATA_ENABLED", "True")) == "True"
        self.eve_path = str(config.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"))
        self.poll_interval = max(0.1, float(config.get("SURICATA_POLL_INTERVAL", 0.5)))
        self.interface = str(config.get("SURICATA_INTERFACE", "eth0"))
        excluded = str(config.get("SURICATA_BLOCK_EXCLUDED_SIDS", "") or "")
        self.excluded_sids = {int(x.strip()) for x in excluded.split(",")
                              if x.strip().isdigit()}
        self.running = False
        self.events = deque(maxlen=200)
        self.skipped = Counter()      # alert 가 아닌 이벤트 종류별 수
        self.stats = {"parsed": 0, "invalid": 0, "alerts": 0, "status": "stopped"}
        self._system_cache = ({}, 0.0)

    # ── 생명주기 ──────────────────────────────────────────────
    def start(self, demo=False):
        # Suricata 는 합성 이벤트를 만들지 않는다 — 없으면 'waiting' 으로 정직하게 둔다
        if self.running or not self.enabled:
            if not self.enabled:
                self.stats["status"] = "disabled"
            return
        self.running = True
        self.stats["status"] = "active" if os.path.exists(self.eve_path) else "waiting"
        threading.Thread(target=self._tail_loop, daemon=True, name="suricata-tail").start()
        _log.info(f"[Suricata] eve.json 감시: {self.eve_path} ({self.stats['status']})")

    def stop(self):
        self.running = False

    # ── 상태 ──────────────────────────────────────────────────
    def get_status(self):
        system, cached_at = self._system_cache
        now = time.time()
        if now - cached_at >= 5:
            system = {"suricata_service": self._service_state("suricata"),
                      "interface": self.interface}
            self._system_cache = (system, now)
        quality = []
        store = getattr(self.threat_detector, "store", None)
        if store is not None and hasattr(store, "sid_stats"):
            quality = store.sid_stats("SURICATA_ALERT", limit=30)
        return {**self.stats, "enabled": self.enabled, "eve_path": self.eve_path,
                "mode": "real" if self.stats["status"] == "active" else "off",
                "recent": list(self.events)[:20], "system": system,
                "skipped_by_type": dict(self.skipped.most_common(8)),
                "excluded_sids": sorted(self.excluded_sids), "sid_quality": quality}

    @staticmethod
    def _service_state(name):
        def run(action):
            try:
                out = subprocess.run(["systemctl", action, name], capture_output=True,
                                     text=True, timeout=2, check=False)
                return (out.stdout or out.stderr).strip().splitlines()[0]
            except (OSError, subprocess.TimeoutExpired, IndexError):
                return "unknown"
        return {"active": run("is-active"), "enabled": run("is-enabled")}

    # ── 수집 ──────────────────────────────────────────────────
    def ingest_line(self, line):
        parsed = parse_eve_line(line)
        if parsed is None:
            self.stats["invalid"] += 1
            return None
        if isinstance(parsed, tuple):           # alert 가 아닌 이벤트
            self.skipped[parsed[1]] += 1
            return None
        event = parsed
        self.stats["parsed"] += 1
        self.events.appendleft(event)
        self.socketio.emit("suricata_alert", event)
        if self.threat_detector:
            severity = _SEVERITY.get(event["severity"], "MEDIUM")
            details = {
                "source": "suricata", "sensor": "suricata",
                "signature_id": event["sid"], "generator_id": event["gid"],
                "revision": event["rev"], "category": event["category"],
                "severity_raw": event["severity"], "action": event["action"],
                "protocol": event["protocol"], "app_proto": event["app_proto"],
                "src_port": event["src_port"], "dst_port": event["dst_port"],
                "http_host": event["http_host"], "http_url": event["http_url"],
                "dns_query": event["dns_query"], "flow_id": event["flow_id"],
                "evidence": ["suricata_signature"], "demo": False,
            }
            if event["sid"] in self.excluded_sids:
                details["block_excluded"] = True
                details["evidence"] = []
            ctx = ""
            if event["http_host"] or event["http_url"]:
                ctx = f" — {event['http_host'] or ''}{event['http_url'] or ''}"
            elif event["dns_query"]:
                ctx = f" — DNS {event['dns_query']}"
            self.threat_detector.report_alert(
                "SURICATA_ALERT", severity, event["src_ip"], event["dst_ip"],
                f"[Suricata SID {event['sid']}] {event['signature']}{ctx}", details)
            self.stats["alerts"] += 1
        return event

    def _tail_loop(self):
        handle = None
        inode = None
        while self.running:
            try:
                stat = os.stat(self.eve_path)
                if handle is None or inode != stat.st_ino:   # 최초 열기 또는 로테이션
                    if handle:
                        handle.close()
                    handle = open(self.eve_path, "r", encoding="utf-8", errors="replace")
                    handle.seek(0, os.SEEK_END)
                    inode = stat.st_ino
                    self.stats["status"] = "active"
                line = handle.readline()
                if line:
                    if line.endswith("\n"):          # 쓰다 만 줄은 다음 turn 에
                        self.ingest_line(line)
                    else:
                        handle.seek(handle.tell() - len(line.encode("utf-8", "replace")))
                        time.sleep(self.poll_interval)
                    continue
            except (FileNotFoundError, PermissionError):
                self.stats["status"] = "waiting"
                if handle:
                    handle.close()
                    handle = None
            except OSError:
                self.stats["status"] = "error"
            time.sleep(self.poll_interval)
        if handle:
            handle.close()
