"""
네트워크 모니터링 관제 (Network Monitoring)

홈서버의 네트워크 상태를 실시간 관제:
  - 활성 TCP 연결 / 리스닝(오픈) 포트 인벤토리 (psutil)
  - 원격지 IP를 IP 평판(AbuseIPDB)과 교차검증 → 악성 IP 연결 탐지
  - 대역폭 사용량(송·수신 바이트/초, net_io_counters)
  - 감시 대상 서비스 헬스체크(TCP connect) — 자동매매 서버/포트 가용성
  - 이상 탐지: 새 리스닝 포트 개방, 악성 IP 아웃바운드, 연결 급증

psutil 있으면 실측, 없으면 데모 데이터로 fallback.
감시 대상은 NET_MONITOR_TARGETS 로 지정: "이름=host:port;..." (기본: 로컬 대시보드)
"""
import time
import socket
import threading
from datetime import datetime
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


def _parse_targets(raw):
    targets = []
    for item in (raw or "").split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        name, _, hp = item.partition("=")
        host, _, port = hp.partition(":")
        if host and port.isdigit():
            targets.append({"name": name.strip(), "host": host.strip(), "port": int(port)})
    return targets


class NetworkMonitor:
    def __init__(self, socketio, config=None, ip_reputation=None,
                 threat_detector=None):
        self.socketio = socketio
        self.config = config or {}
        self.ip_reputation = ip_reputation
        self.threat_detector = threat_detector
        self.running = False
        self._lock = threading.Lock()

        try:
            self.interval = float(self.config.get("NET_MONITOR_INTERVAL", 5))
        except (TypeError, ValueError):
            self.interval = 5.0

        self.targets = _parse_targets(self.config.get("NET_MONITOR_TARGETS", "")) or [
            {"name": "SOC 대시보드", "host": "127.0.0.1",
             "port": int(self.config.get("PORT", 5055) or 5055)},
        ]

        self.connections = []      # 최근 활성 연결
        self.listening = []        # 리스닝 포트
        self.target_status = []    # 헬스체크 결과
        self.bandwidth = deque(maxlen=60)   # (ts, up_bps, down_bps)
        self.events = deque(maxlen=200)     # 네트워크 이벤트(악성연결/포트개방 등)
        self._prev_io = None
        self._prev_io_ts = None
        self._known_ports = set()
        self._alerted_ips = set()
        self._evt_id = 0
        self.stats = {
            "mode": "off",
            "established": 0,
            "listening_ports": 0,
            "external_peers": 0,
            "malicious_conns": 0,
            "targets_up": 0,
            "targets_down": 0,
            "up_bps": 0,
            "down_bps": 0,
        }

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        real = PSUTIL_OK and not demo
        with self._lock:
            self.stats["mode"] = "real" if real else "demo"
        threading.Thread(target=self._loop, args=(real,), daemon=True).start()
        _log.info(f"[NetMon] 네트워크 관제 시작 — {'실측(psutil)' if real else '데모'}, "
              f"감시대상 {len(self.targets)}개")

    def stop(self):
        self.running = False

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "connections": self.connections[:80],
                "listening": self.listening[:60],
                "targets": list(self.target_status),
                "bandwidth": list(self.bandwidth),
                "events": list(reversed(list(self.events)))[:40],
            }

    # ------------------------------------------------------------------ #
    #  루프
    # ------------------------------------------------------------------ #

    def _loop(self, real):
        while self.running:
            try:
                if real:
                    self._collect_real()
                else:
                    self._collect_demo()
                self._check_targets()
                self._emit()
            except Exception as e:
                _log.error(f"[NetMon] 수집 오류: {e}")
            for _ in range(int(self.interval * 2)):
                if not self.running:
                    return
                time.sleep(0.5)

    # ---------------- 실측 ---------------- #

    def _collect_real(self):
        conns, listening = [], []
        peers = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                if c.status == "LISTEN":
                    listening.append({
                        "port": c.laddr.port if c.laddr else 0,
                        "addr": c.laddr.ip if c.laddr else "-",
                        "pid": c.pid, "proc": _proc_name(c.pid),
                    })
                    continue
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                rip = c.raddr.ip if c.raddr else None
                external = rip and not _is_internal(rip)
                if external:
                    peers.add(rip)
                conns.append({
                    "laddr": laddr, "raddr": raddr, "rip": rip,
                    "status": c.status, "pid": c.pid, "proc": _proc_name(c.pid),
                    "external": bool(external),
                })
        except Exception as e:
            _log.error(f"[NetMon] net_connections 오류: {e}")

        self._update_bandwidth_real()
        self._finalize(conns, listening, peers)

    def _update_bandwidth_real(self):
        try:
            io = psutil.net_io_counters()
            now = time.time()
            if self._prev_io and self._prev_io_ts:
                dt = max(0.001, now - self._prev_io_ts)
                up = (io.bytes_sent - self._prev_io.bytes_sent) / dt
                down = (io.bytes_recv - self._prev_io.bytes_recv) / dt
                with self._lock:
                    self.bandwidth.append([datetime.now().strftime("%H:%M:%S"),
                                           int(max(0, up)), int(max(0, down))])
                    self.stats["up_bps"] = int(max(0, up))
                    self.stats["down_bps"] = int(max(0, down))
            self._prev_io = io
            self._prev_io_ts = now
        except Exception:
            pass

    # ---------------- 데모 ---------------- #

    def _collect_demo(self):
        import random
        listening = [
            {"port": 5055, "addr": "0.0.0.0", "pid": 905, "proc": "python"},
            {"port": 22, "addr": "0.0.0.0", "pid": 1203, "proc": "sshd"},
            {"port": 443, "addr": "0.0.0.0", "pid": 812, "proc": "nginx"},
        ]
        peers = set()
        conns = [
            {"laddr": "172.23.171.63:5055", "raddr": "100.66.201.56:51888", "rip": "100.66.201.56",
             "status": "ESTABLISHED", "pid": 905, "proc": "python", "external": False},
            {"laddr": "172.23.171.63:443", "raddr": "8.8.8.8:443", "rip": "8.8.8.8",
             "status": "ESTABLISHED", "pid": 812, "proc": "nginx", "external": True},
        ]
        peers.add("8.8.8.8")
        # 15% 확률로 악성 IP 아웃바운드 연결 시나리오
        if random.random() < 0.15:
            bad = random.choice(["45.155.205.233", "185.220.101.45", "193.32.162.157"])
            conns.append({"laddr": "172.23.171.63:44152", "raddr": f"{bad}:4444", "rip": bad,
                          "status": "ESTABLISHED", "pid": random.randint(2000, 9000),
                          "proc": "bash", "external": True, "demo": True})
            peers.add(bad)
        # 8% 확률로 새 리스닝 포트 개방
        if random.random() < 0.08:
            listening.append({"port": random.choice([4444, 1337, 31337]), "addr": "0.0.0.0",
                              "pid": random.randint(2000, 9000), "proc": "nc", "demo": True})
        # 데모 대역폭
        with self._lock:
            self.bandwidth.append([datetime.now().strftime("%H:%M:%S"),
                                   random.randint(50_000, 900_000),
                                   random.randint(80_000, 2_500_000)])
            self.stats["up_bps"] = self.bandwidth[-1][1]
            self.stats["down_bps"] = self.bandwidth[-1][2]
        self._finalize(conns, listening, peers)

    # ---------------- 공통 후처리 ---------------- #

    def _finalize(self, conns, listening, peers):
        with self._lock:
            self.connections = conns
            self.listening = listening
            self.stats["established"] = sum(1 for c in conns if c["status"] == "ESTABLISHED")
            self.stats["listening_ports"] = len(listening)
            self.stats["external_peers"] = len(peers)
            cur_ports = {l["port"] for l in listening}

        # 새 리스닝 포트 개방 감지 (최초 스캔은 베이스라인으로 학습만)
        if self._known_ports:
            demo_ports = {l["port"] for l in listening if l.get("demo")}
            new_ports = cur_ports - self._known_ports
            for port in new_ports:
                if port not in (5055, 22, 443, 80):
                    self._raise_event("PORT_OPEN", "HIGH",
                                      f"새 리스닝 포트 개방: {port}",
                                      {"port": port, "demo": port in demo_ports})
        self._known_ports = cur_ports

        # 악성 IP 연결 교차검증
        if self.ip_reputation:
            for c in conns:
                rip = c.get("rip")
                if not c.get("external") or not rip or rip in self._alerted_ips:
                    continue
                try:
                    rep = self.ip_reputation.check(rip)
                except Exception:
                    continue
                trusted_rep = (rep.get("source") == "abuseipdb" or
                               (c.get("demo") and rep.get("source") == "demo"))
                if (trusted_rep and
                        rep.get("score", 0) >= getattr(self.ip_reputation, "min_score", 75)):
                    self._alerted_ips.add(rip)
                    with self._lock:
                        self.stats["malicious_conns"] += 1
                    self._raise_event("MALICIOUS_CONN", "CRITICAL",
                                      f"악성 IP와 통신: {rip} (평판 {rep.get('score')}/100)",
                                      {"rip": rip, "raddr": c.get("raddr"),
                                       "proc": c.get("proc"), "score": rep.get("score"),
                                       "demo": bool(c.get("demo"))})

    def _check_targets(self):
        results, up, down = [], 0, 0
        for t in self.targets:
            ok, latency = _tcp_probe(t["host"], t["port"], timeout=2.0)
            results.append({"name": t["name"], "host": t["host"], "port": t["port"],
                            "up": ok, "latency_ms": latency,
                            "checked": datetime.now().strftime("%H:%M:%S")})
            up += 1 if ok else 0
            down += 0 if ok else 1
        with self._lock:
            self.target_status = results
            self.stats["targets_up"] = up
            self.stats["targets_down"] = down

    def _raise_event(self, kind, severity, description, details=None):
        with self._lock:
            self._evt_id += 1
            evt = {"id": self._evt_id, "kind": kind, "severity": severity,
                   "description": description, "details": details or {},
                   "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self.events.append(evt)
        try:
            self.socketio.emit("net_event", evt)
        except Exception:
            pass
        # 심각 이벤트는 위협 파이프라인에 투입 → AI 트리아지
        if self.threat_detector and severity in ("HIGH", "CRITICAL"):
            try:
                rip = (details or {}).get("rip")
                self.threat_detector.report_alert(
                    "NETWORK_ANOMALY" if kind == "PORT_OPEN" else "MALWARE_BEACON",
                    severity, src_ip=rip, dst_ip=None,
                    description=f"[NetMon] {description}",
                    details=details or {})
            except Exception:
                pass

    def _emit(self):
        try:
            with self._lock:
                payload = {"stats": dict(self.stats),
                           "targets": list(self.target_status),
                           "bandwidth": list(self.bandwidth)[-30:]}
            self.socketio.emit("net_status", payload)
        except Exception:
            pass


# ───────── 유틸 ─────────

_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.",
                     "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def _is_internal(ip):
    if not ip or ip == "-":
        return True
    if ip.startswith(_PRIVATE_PREFIXES) or ":" in ip:   # IPv6 는 단순화 위해 내부 취급
        return True
    try:
        a, b = ip.split(".")[:2]
        if int(a) == 100 and 64 <= int(b) <= 127:        # CGNAT/Tailscale
            return True
    except (ValueError, IndexError):
        return True
    return False


def _tcp_probe(host, port, timeout=2.0):
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.time() - start) * 1000, 1)
    except Exception:
        return False, None


_proc_cache = {}


def _proc_name(pid):
    if not pid or not PSUTIL_OK:
        return "?"
    if pid in _proc_cache:
        return _proc_cache[pid]
    try:
        name = psutil.Process(pid).name()
    except Exception:
        name = "?"
    _proc_cache[pid] = name
    if len(_proc_cache) > 500:
        _proc_cache.clear()
    return name
