"""
허니팟 (Honeypot) 모듈 — 유인 서비스로 침해시도 능동 포착

공격자가 흔히 노리는 서비스(SSH/Telnet/HTTP/MySQL/Redis 등)를 흉내 내는
가짜 리스너를 열어 둔다. 정상 사용자는 접근할 이유가 없으므로, 여기에 붙는
연결은 사실상 전부 정찰·공격 시도다 → 높은 신뢰도의 침해 지표.

  공격자 ─TCP접속─▶ 허니팟 포트 → 가짜 배너 전송 → 입력(자격증명/명령) 수집
     → honeypot_hit emit + threat_detector.report_alert("HONEYPOT")
       → 신뢰도 → AI 트리아지 → SOAR 차단 → 인시던트 (+ 공격지도 + MITRE)

- 연결만 해도 HIGH, 자격증명/명령 등 상호작용이 있으면 CRITICAL
- 응답은 짧은 가짜 배너만 보내고 즉시 종료(실서비스 흉내는 최소화 → 안전)
- 바인딩 실패(포트 점유 등)나 데모 모드면 데모 fallback (CLAUDE.md 규칙)

⚠ 실제 공격을 잡으려면 0.0.0.0 바인드 + 외부 노출(Tailscale/방화벽 포워딩)이
   필요하다. 기본은 안전하게 로컬(127.0.0.1) 바인드.
"""
import re
import time
import socket
import random
import threading
from datetime import datetime
from collections import deque, Counter

from modules.access_log_parser import _PRIVATE_PREFIXES

from modules.logging_setup import get_logger

_log = get_logger(__name__)

# 포트 → (서비스명, 배너, MITRE 유형 힌트)
SERVICE_PROFILES = {
    22:    ("SSH",    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
    2222:  ("SSH",    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
    23:    ("Telnet", b"\xff\xfd\x18\xff\xfd \xff\xfd#\xff\xfd'login: "),
    2323:  ("Telnet", b"\xff\xfd\x18login: "),
    3306:  ("MySQL",  b"\x4a\x00\x00\x00\x0a5.7.40\x00"),
    6379:  ("Redis",  b"-NOAUTH Authentication required.\r\n"),
    8081:  ("HTTP",   b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\n\r\n"),
    9200:  ("Elasticsearch", b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"node-1\"}"),
    5900:  ("VNC",    b"RFB 003.008\n"),
}

DEFAULT_PORTS = "2222,2323,3306,6379,8081,9200"


class Honeypot:
    """유인 서비스 리스너 — start()/stop()/get_events()/get_status() 인터페이스"""

    def __init__(self, socketio, config=None, threat_detector=None,
                 mitre_tracker=None, attack_map=None):
        self.socketio = socketio
        self.config = config or {}
        self.threat_detector = threat_detector
        self.mitre = mitre_tracker
        self.attack_map = attack_map
        self.running = False
        self._lock = threading.Lock()
        self._socks = []

        self.enabled = str(self.config.get("HONEYPOT_ENABLED", "True")).lower() == "true"
        self.bind = self.config.get("HONEYPOT_BIND", "127.0.0.1")
        raw = self.config.get("HONEYPOT_PORTS") or DEFAULT_PORTS
        self.ports = []
        for p in str(raw).split(","):
            p = p.strip()
            if p.isdigit():
                self.ports.append(int(p))

        self.cooldown = float(self.config.get("HONEYPOT_COOLDOWN", 30))  # 동일 IP 재알림 간격

        # 동시 처리 상한 — 연결마다 스레드를 만들되 개수를 묶는다.
        # 상한이 없으면 문서가 권장하는 HONEYPOT_BIND=0.0.0.0 외부 노출 시
        # 초당 수천 연결로 대시보드 자신이 스레드 고갈로 죽는다(AUDIT B-5).
        # 유인 서비스라 공격자가 마음껏 연결할 수 있다는 점이 핵심이다.
        try:
            self.max_conns = max(1, int(self.config.get("HONEYPOT_MAX_CONNS", 200)))
        except (TypeError, ValueError):
            self.max_conns = 200
        self._slots = threading.BoundedSemaphore(self.max_conns)
        self.events = deque(maxlen=1000)
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self._alerted = {}   # ip → 마지막 알림 ts
        self.stats = {
            "total_hits": 0, "interactions": 0, "unique_ips": 0,
            "alerts": 0, "ports_open": 0, "mode": "-",
            "bind": self.bind, "last_hit": None,
            # 상한 초과로 즉시 끊은 연결 — 0이 아니면 공격 규모가 상한을 넘었다는 신호
            "rejected": 0, "max_conns": self.max_conns, "active_conns": 0,
        }
        self._server_ip = self._detect_server_ip()

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        opened = self._bind_listeners() if self.enabled else []
        self.stats["ports_open"] = len(opened)

        if opened:
            self.stats["mode"] = "real"
            _log.info(f"[Honeypot] 유인 서비스 오픈: {self.bind} 포트 {opened}")
            if demo:   # 전역 데모 모드면 시연용 합성 히트도 주입(라벨 구분)
                threading.Thread(target=self._demo_loop, daemon=True).start()
        elif demo:
            self.stats["mode"] = "demo"
            _log.warning("[Honeypot] 포트 바인딩 불가 — 데모 모드")
            threading.Thread(target=self._demo_loop, daemon=True).start()
        else:
            self.stats["mode"] = "off"
            _log.warning("[Honeypot] 포트 바인딩 불가 — 비활성")

    def stop(self):
        self.running = False
        for s in self._socks:
            try:
                s.close()
            except Exception:
                pass
        self._socks = []

    def get_events(self, limit=100, source=None):
        with self._lock:
            evs = list(self.events)
        if source:
            evs = [e for e in evs if e["service"] == source]
        return list(reversed(evs))[:limit]

    def get_stats(self):
        with self._lock:
            stats = dict(self.stats)
            stats["unique_ips"] = len(self.ip_counter)
            stats["top_ips"] = self.ip_counter.most_common(10)
            stats["by_service"] = self.port_counter.most_common()
            stats["ports"] = self.ports
        return stats

    def get_status(self):
        return {
            "stats": self.get_stats(),
            "config": {"enabled": self.enabled, "bind": self.bind, "ports": self.ports},
            "events": self.get_events(100),
        }

    # ------------------------------------------------------------------ #
    #  리스너
    # ------------------------------------------------------------------ #

    def _bind_listeners(self):
        opened = []
        for port in self.ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.bind, port))
                s.listen(8)
                s.settimeout(1.0)
                self._socks.append(s)
                threading.Thread(target=self._accept_loop, args=(s, port),
                                 daemon=True).start()
                opened.append(port)
            except OSError as e:
                _log.warning(f"[Honeypot] 포트 {port} 바인딩 실패: {e}")
        return opened

    def _accept_loop(self, sock, port):
        service = SERVICE_PROFILES.get(port, ("Unknown", b""))[0]
        while self.running:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # 상한에 걸리면 접촉만 기록하고 즉시 끊는다. 배너 교환·입력 수집을
            # 포기하더라도 "이 IP 가 접촉했다"는 탐지 가치는 지킨다.
            if not self._slots.acquire(blocking=False):
                ip = addr[0]
                try:
                    conn.close()
                except OSError:
                    pass
                with self._lock:
                    self.stats["rejected"] += 1
                self._record(ip, port, service, "", demo=False, rejected=True)
                continue
            threading.Thread(target=self._handle_conn, args=(conn, addr[0], port, service),
                             daemon=True).start()

    def _handle_conn(self, conn, ip, port, service):
        with self._lock:
            self.stats["active_conns"] += 1
        try:
            self._interact(conn, ip, port, service)
        finally:
            with self._lock:
                self.stats["active_conns"] -= 1
            self._slots.release()

    def _interact(self, conn, ip, port, service):
        banner = SERVICE_PROFILES.get(port, ("Unknown", b""))[1]
        payload = ""
        try:
            conn.settimeout(3.0)
            if banner:
                try:
                    conn.sendall(banner)
                except OSError:
                    pass
            # 공격자 입력(자격증명/명령) 최대 512바이트 수집
            try:
                data = conn.recv(512)
                if data:
                    payload = data.decode("utf-8", "replace")
            except (socket.timeout, OSError):
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
        self._record(ip, port, service, payload, demo=False)

    # ------------------------------------------------------------------ #

    def _record(self, ip, port, service, payload, demo=False, rejected=False):
        interacted = bool(payload.strip())
        severity = "CRITICAL" if interacted else "HIGH"
        summary = _sanitize(payload)[:200] if interacted else "(연결만, 입력 없음)"
        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip, "port": port, "service": service,
            "interacted": interacted, "severity": severity,
            # 상한 초과로 상호작용 없이 끊은 접촉임을 표시한다
            "rejected": rejected,
            "payload": summary, "demo": demo,
        }
        with self._lock:
            self.events.append(event)
            self.ip_counter[ip] += 1
            self.port_counter[f"{service}:{port}"] += 1
            self.stats["total_hits"] += 1
            if interacted:
                self.stats["interactions"] += 1
            self.stats["last_hit"] = event["timestamp"]

        self.socketio.emit("honeypot_hit", event)

        # 허니팟 접촉은 사실상 전부 악성 → 파이프라인 주입 (내부 IP 제외, 쿨다운)
        if self._is_external(ip):
            self._escalate(event)

    def _escalate(self, event):
        ip = event["ip"]
        now = time.time()
        with self._lock:
            if now - self._alerted.get(ip, 0) < self.cooldown:
                return
            self._alerted[ip] = now
            self.stats["alerts"] += 1

        if self.attack_map:
            try:
                self.attack_map.add_attack_ip(ip, "HONEYPOT", event["severity"])
            except Exception:
                pass
        if self.mitre:
            try:
                self.mitre.map_threat("PORT_SCAN", src_ip=ip,
                                      description=f"[Honeypot] {event['service']} 유인 접촉")
            except Exception:
                pass
        if self.threat_detector:
            try:
                desc = f"[Honeypot] {event['service']}(:{event['port']}) 유인 서비스 접촉 — {ip}"
                if event["interacted"]:
                    desc += f" · 입력: {event['payload'][:80]}"
                self.threat_detector.report_alert(
                    "HONEYPOT", event["severity"], ip, self._server_ip, desc,
                    {"source": "honeypot", "service": event["service"],
                     "port": event["port"], "interacted": event["interacted"],
                     "payload": event["payload"], "demo": event.get("demo", False),
                     "evidence": ([] if event.get("demo") else
                                  ["honeypot_interaction" if event["interacted"]
                                   else "honeypot_contact"])})
            except Exception as e:
                _log.error(f"[Honeypot] 알림 전달 오류: {e}")

    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_external(ip):
        return bool(ip) and not ip.startswith(_PRIVATE_PREFIXES)

    @staticmethod
    def _detect_server_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ------------------------------------------------------------------ #
    #  데모 fallback
    # ------------------------------------------------------------------ #

    _DEMO_PAYLOADS = {
        "SSH": ["root:admin123", "admin:password", "root:123456", ""],
        "Telnet": ["root\r\nroot\r\n", "admin\r\n", ""],
        "Redis": ["CONFIG SET dir /var/spool/cron/", "INFO\r\n", ""],
        "MySQL": ["", "root"],
        "HTTP": ["GET /admin HTTP/1.1", "POST /login user=admin&pass=admin"],
        "Elasticsearch": ["GET /_cat/indices", ""],
        "VNC": [""],
    }

    def _demo_loop(self):
        time.sleep(3)
        while self.running:
            port = random.choice(self.ports) if self.ports else random.choice(list(SERVICE_PROFILES))
            service = SERVICE_PROFILES.get(port, ("SSH", b""))[0]
            ip = f"{random.randint(1,223)}.{random.randint(0,254)}." \
                 f"{random.randint(0,254)}.{random.randint(1,254)}"
            payload = random.choice(self._DEMO_PAYLOADS.get(service, [""]))
            self._record(ip, port, service, payload, demo=True)
            time.sleep(random.uniform(5.0, 12.0))


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize(text):
    """제어문자 이스케이프 (배너/바이너리 프로브 안전 표시)."""
    return _CTRL_RE.sub(lambda m: "\\x%02x" % ord(m.group()), text)
