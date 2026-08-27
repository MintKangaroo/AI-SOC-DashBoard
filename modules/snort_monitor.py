"""Snort fast-alert 로그를 SOC 알림 파이프라인으로 전달한다.

Snort는 탐지 근거 하나를 제공할 뿐 차단을 직접 수행하지 않는다. 차단 여부는
SOAR의 복수 근거·고신뢰·분석가 승인 게이트에서 별도로 결정한다.
"""
import os
import re
import subprocess
import threading
import time
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)


_FAST_ALERT = re.compile(
    r"^\s*(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<message>.*?)\s+\[\*\*\].*?"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>[^}]+)\}\s+"
    r"(?P<src>\S+)\s+->\s+(?P<dst>\S+)\s*$",
    re.IGNORECASE,
)


def _split_endpoint(value):
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        host, _, port = value[1:].partition("]:")
        return host, int(port) if port.isdigit() else None
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return value.strip("[]"), None


def parse_fast_alert(line):
    """Snort 2/3 ``-A fast`` 한 줄을 정규화한다."""
    match = _FAST_ALERT.match(line)
    if not match:
        return None
    data = match.groupdict()
    src_ip, src_port = _split_endpoint(data.pop("src"))
    dst_ip, dst_port = _split_endpoint(data.pop("dst"))
    data.update({
        "gid": int(data["gid"]), "sid": int(data["sid"]),
        "rev": int(data["rev"]), "priority": int(data["priority"]),
        "src_ip": src_ip, "src_port": src_port,
        "dst_ip": dst_ip, "dst_port": dst_port,
    })
    return data


class SnortMonitor:
    def __init__(self, socketio, config=None, threat_detector=None):
        config = config or {}
        self.socketio = socketio
        self.threat_detector = threat_detector
        self.enabled = str(config.get("SNORT_ENABLED", "True")) == "True"
        self.alert_path = str(config.get(
            "SNORT_ALERT_PATH", "/var/log/snort/snort.alert.fast"))
        self.poll_interval = max(0.1, float(config.get("SNORT_POLL_INTERVAL", 0.5)))
        self.interface = str(config.get("SNORT_INTERFACE", "eth0"))
        self.home_net = str(config.get("SNORT_HOME_NET", "172.23.160.0/20"))
        excluded = str(config.get("SNORT_BLOCK_EXCLUDED_SIDS", "254"))
        self.excluded_sids = {int(x.strip()) for x in excluded.split(",")
                              if x.strip().isdigit()}
        self.running = False
        self.events = deque(maxlen=200)
        self.stats = {"parsed": 0, "invalid": 0, "alerts": 0, "status": "stopped"}
        self._system_cache = ({}, 0.0)

    def start(self, demo=False):
        if self.running or not self.enabled:
            self.stats["status"] = "disabled" if not self.enabled else self.stats["status"]
            return
        self.running = True
        self.stats["status"] = "waiting" if not os.path.exists(self.alert_path) else "active"
        threading.Thread(target=self._tail_loop, daemon=True).start()
        _log.info(f"[Snort] fast-alert 감시: {self.alert_path} ({self.stats['status']})")

    def stop(self):
        self.running = False

    def get_status(self):
        system, cached_at = self._system_cache
        now = time.time()
        if now - cached_at >= 5:
            system = {
                "snort_service": self._service_state("snort"),
                "ufw_service": self._service_state("ufw"),
                "interface": self.interface,
                "home_net": self.home_net,
                "firewall_policy": "deny incoming / allow outgoing",
                "protected_paths": ["SSH 22", "HTTP 80", "Tailscale", "Dashboard 5055"],
            }
            self._system_cache = (system, now)
        quality = []
        store = getattr(self.threat_detector, "store", None)
        if store:
            quality = store.snort_sid_stats(limit=30)
        return {**self.stats, "enabled": self.enabled, "alert_path": self.alert_path,
                "recent": list(self.events)[:20], "system": system,
                "excluded_sids": sorted(self.excluded_sids), "sid_quality": quality}

    @staticmethod
    def _service_state(name):
        def run(action):
            try:
                out = subprocess.run(
                    ["systemctl", action, name], capture_output=True, text=True,
                    timeout=2, check=False)
                return (out.stdout or out.stderr).strip().splitlines()[0]
            except (OSError, subprocess.TimeoutExpired, IndexError):
                return "unknown"
        return {"active": run("is-active"), "enabled": run("is-enabled")}

    def ingest_line(self, line):
        event = parse_fast_alert(line)
        if not event:
            self.stats["invalid"] += 1
            return None
        self.stats["parsed"] += 1
        self.events.appendleft(event)
        self.socketio.emit("snort_alert", event)
        if self.threat_detector:
            priority = event["priority"]
            severity = "CRITICAL" if priority == 1 else "HIGH" if priority == 2 else "MEDIUM"
            details = {
                "source": "snort", "sensor": "snort", "signature_id": event["sid"],
                "generator_id": event["gid"], "revision": event["rev"],
                "priority": priority, "protocol": event["protocol"],
                "src_port": event["src_port"], "dst_port": event["dst_port"],
                "evidence": ["snort_signature"], "demo": False,
            }
            if event["sid"] in self.excluded_sids:
                details["block_excluded"] = True
                details["evidence"] = []
            self.threat_detector.report_alert(
                "SNORT_ALERT", severity, event["src_ip"], event["dst_ip"],
                f"[Snort SID {event['sid']}] {event['message']}", details)
            self.stats["alerts"] += 1
        return event

    def _tail_loop(self):
        handle = None
        inode = None
        while self.running:
            try:
                stat = os.stat(self.alert_path)
                if handle is None or inode != stat.st_ino:
                    if handle:
                        handle.close()
                    handle = open(self.alert_path, "r", encoding="utf-8", errors="replace")
                    handle.seek(0, os.SEEK_END)
                    inode = stat.st_ino
                    self.stats["status"] = "active"
                line = handle.readline()
                if line:
                    self.ingest_line(line.rstrip())
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
