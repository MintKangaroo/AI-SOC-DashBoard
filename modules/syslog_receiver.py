"""
Syslog 수신 모듈 (침해시도 원격 수집)

외부 프로젝트(자동매매 KR/USA 등)가 접속 시도·보안 이벤트를 syslog 프로토콜로
전송하면, 이 모듈이 UDP + TCP 로 수신·파싱해 SOC 파이프라인에 주입한다.

  KR/USA (SysLogHandler) ──syslog──▶ 127.0.0.1:5514 ──▶ SyslogReceiver
     → RFC3164/RFC5424 파싱 → 접속시도/공격 분류
     → 의심 이벤트는 threat_detector.report_alert() 로 전체 파이프라인 연동
       (신뢰도 → AI 트리아지 → SOAR → 인시던트) + 공격지도 + MITRE 매핑

파일 tail(access_log_parser) 방식과 달리 로그 위치가 바뀌어도 깨지지 않는다.
포트 바인딩에 실패하면 데모 fallback (CLAUDE.md 규칙).
"""
import re
import time
import socket
import random
import threading
from datetime import datetime
from collections import deque, Counter

from modules.access_log_parser import classify_request, _PRIVATE_PREFIXES

from modules.logging_setup import get_logger

_log = get_logger(__name__)

_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
# <PRI> 접두 (RFC3164/5424 공통). PRI = facility*8 + severity
_PRI_RE = re.compile(r"^<(\d{1,3})>")
# RFC5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG
_RFC5424_RE = re.compile(
    r"^(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?:\[.*?\]|-)\s?(?P<msg>.*)$")
# RFC3164: <PRI>Mmm dd hh:mm:ss HOST TAG: MSG
_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[]+?)(?:\[\d+\])?:\s?(?P<msg>.*)$")

# werkzeug/http.server 접근 라인 (메시지 본문에 그대로 실려 오는 경우)
_ACCESS_RE = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}) - - \[[^\]]+\] "(.*)" (\d{3})')

_SEVERITY_NAME = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

# 메시지 본문 키워드 → (suspicious, severity, category)
_KEYWORD_RULES = [
    (("failed password", "authentication failure", "invalid user", "brute"),
     True, "HIGH", "인증 실패/무차별 대입"),
    (("unauthorized", "403 forbidden", "permission denied", "access denied"),
     True, "MEDIUM", "권한 없는 접근 시도"),
    (("sql injection", "union select", "' or '1'='1", "sqlmap"),
     True, "CRITICAL", "SQL 인젝션 시도"),
    (("<script>", "xss", "onerror=", "javascript:"),
     True, "HIGH", "XSS 시도"),
    (("../", "..%2f", "/etc/passwd", "path traversal"),
     True, "HIGH", "경로 탐색 시도"),
    (("port scan", "nmap", "masscan", "syn scan"),
     True, "HIGH", "포트 스캔"),
    (("malware", "reverse shell", "/bin/sh", "webshell", "c2 ", "command and control"),
     True, "CRITICAL", "악성코드/C2 의심"),
]


def classify_syslog(message):
    """syslog 메시지 본문 → (suspicious, severity, category, src_ip)

    1) werkzeug 접근 라인이면 access_log_parser 분류 재사용
    2) 아니면 보안 키워드 규칙
    """
    src_ip = None
    m = _ACCESS_RE.match(message.strip())
    if m:
        src_ip, request, status = m.group(1), m.group(2), int(m.group(3))
        suspicious, severity, category = classify_request(request, status)
        return suspicious, severity, category, src_ip

    low = message.lower()
    for kws, susp, sev, cat in _KEYWORD_RULES:
        if any(k in low for k in kws):
            ipm = _IP_RE.search(message)
            return susp, sev, cat, (ipm.group(1) if ipm else None)

    ipm = _IP_RE.search(message)
    return False, "INFO", "일반 이벤트", (ipm.group(1) if ipm else None)


class SyslogReceiver:
    """UDP+TCP syslog 수신기 — start()/stop()/get_events()/get_status() 인터페이스"""

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

        self.enabled = str(self.config.get("SYSLOG_ENABLED", "True")).lower() == "true"
        self.bind = self.config.get("SYSLOG_BIND", "127.0.0.1")
        self.port = int(self.config.get("SYSLOG_PORT", 5514))

        self.events = deque(maxlen=1000)
        self.ip_counter = Counter()
        self.host_counter = Counter()
        # 동시 TCP 연결 상한. syslog 연결은 30초 타임아웃으로 오래 살아 있어
        # 허니팟보다 적은 연결로도 스레드가 쌓인다(AUDIT B-5).
        try:
            self.max_conns = max(1, int(self.config.get("SYSLOG_MAX_CONNS", 50)))
        except (TypeError, ValueError):
            self.max_conns = 50
        self._slots = threading.BoundedSemaphore(self.max_conns)

        self.stats = {
            "total": 0, "suspicious": 0, "received": 0, "demo": 0,
            "unique_ips": 0, "unique_hosts": 0,
            "mode": "-", "bind": f"{self.bind}:{self.port}",
            "last_event": None,
            "rejected": 0, "max_conns": self.max_conns, "active_conns": 0,
        }
        self._server_ip = self._detect_server_ip()

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        listening = False
        if self.enabled:
            listening = self._bind_listeners()

        if listening:
            self.stats["mode"] = "real"
            _log.info(f"[Syslog] 수신 대기 시작: udp/tcp {self.bind}:{self.port}")
            # 실수신 중이어도 전역 데모 모드면 패널 시연용 합성 이벤트 주입(라벨 구분)
            if demo:
                threading.Thread(target=self._demo_loop, daemon=True).start()
        elif demo:
            self.stats["mode"] = "demo"
            _log.warning(f"[Syslog] {self.bind}:{self.port} 바인딩 불가 — 데모 모드")
            threading.Thread(target=self._demo_loop, daemon=True).start()
        else:
            self.stats["mode"] = "off"
            _log.warning(f"[Syslog] {self.bind}:{self.port} 바인딩 불가 — 비활성")

    def stop(self):
        self.running = False
        for s in self._socks:
            try:
                s.close()
            except Exception:
                pass
        self._socks = []

    def get_events(self, limit=100, suspicious_only=False, source=None):
        with self._lock:
            evs = list(self.events)
        if suspicious_only:
            evs = [e for e in evs if e["suspicious"]]
        if source:
            evs = [e for e in evs if e["host"] == source]
        return list(reversed(evs))[:limit]

    def get_stats(self):
        with self._lock:
            stats = dict(self.stats)
            stats["unique_ips"] = len(self.ip_counter)
            stats["unique_hosts"] = len(self.host_counter)
            stats["top_ips"] = self.ip_counter.most_common(10)
            stats["top_hosts"] = self.host_counter.most_common(10)
        return stats

    def get_status(self):
        return {
            "stats": self.get_stats(),
            "config": {"enabled": self.enabled, "bind": self.bind, "port": self.port},
            "events": self.get_events(100),
        }

    # ------------------------------------------------------------------ #
    #  소켓 수신 (UDP + TCP)
    # ------------------------------------------------------------------ #

    def _bind_listeners(self):
        ok = False
        # UDP (고전 syslog)
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            u.bind((self.bind, self.port))
            u.settimeout(1.0)
            self._socks.append(u)
            threading.Thread(target=self._udp_loop, args=(u,), daemon=True).start()
            ok = True
        except OSError as e:
            _log.warning(f"[Syslog] UDP 바인딩 실패: {e}")
        # TCP (유실 방지)
        try:
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            t.bind((self.bind, self.port))
            t.listen(16)
            t.settimeout(1.0)
            self._socks.append(t)
            threading.Thread(target=self._tcp_accept_loop, args=(t,), daemon=True).start()
            ok = True
        except OSError as e:
            _log.warning(f"[Syslog] TCP 바인딩 실패: {e}")
        return ok

    def _udp_loop(self, sock):
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            for line in data.decode("utf-8", "replace").splitlines():
                if line.strip():
                    self._handle(line, peer=addr[0], transport="udp")

    def _tcp_accept_loop(self, sock):
        while self.running:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # 상한 초과 시 즉시 끊는다. syslog 는 전송단이 재시도하므로
            # 로그를 영구히 잃지 않는다(UDP 경로도 함께 열려 있다).
            if not self._slots.acquire(blocking=False):
                try:
                    conn.close()
                except OSError:
                    pass
                with self._lock:
                    self.stats["rejected"] += 1
                continue
            threading.Thread(target=self._tcp_conn_loop, args=(conn, addr[0]),
                             daemon=True).start()

    def _tcp_conn_loop(self, conn, peer):
        with self._lock:
            self.stats["active_conns"] += 1
        try:
            self._tcp_serve(conn, peer)
        finally:
            with self._lock:
                self.stats["active_conns"] -= 1
            self._slots.release()

    def _tcp_serve(self, conn, peer):
        conn.settimeout(30.0)
        buf = ""
        try:
            while self.running:
                try:
                    chunk = conn.recv(8192)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace")
                # 라인 단위(개행) 또는 octet-counting 은 개행 기준으로 단순 처리
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if line.strip():
                        self._handle(line, peer=peer, transport="tcp")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    #  파싱 · 기록
    # ------------------------------------------------------------------ #

    def _parse(self, line):
        """syslog 라인 → (facility, severity_name, host, tag, message)"""
        facility, sev_name = None, None
        rest = line.strip()
        pm = _PRI_RE.match(rest)
        if pm:
            pri = int(pm.group(1))
            facility, sev = pri // 8, pri % 8
            sev_name = _SEVERITY_NAME[sev] if 0 <= sev < 8 else None
            rest = rest[pm.end():]

        m = _RFC5424_RE.match(rest)
        if m and m.group("ver") == "1":
            host = m.group("host")
            tag = m.group("app")
            msg = m.group("msg")
            return facility, sev_name, _clean(host), _clean(tag), msg

        m = _RFC3164_RE.match(rest)
        if m:
            return facility, sev_name, _clean(m.group("host")), \
                _clean(m.group("tag")), m.group("msg")

        # PRI 만 있고 형식 미상 → 전체를 메시지로
        return facility, sev_name, "-", "-", rest

    def _handle(self, line, peer, transport, is_demo=False):
        facility, sev_name, host, tag, message = self._parse(line)
        suspicious, severity, category, src_ip = classify_syslog(message)
        # 메시지에 출발지 IP 가 없으면 전송 피어를 출발지로 사용
        src_ip = src_ip or peer
        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host": host or "-",
            "tag": tag or "-",
            "facility": facility,
            "level": sev_name,
            "ip": src_ip,
            "message": message[:300],
            "transport": transport,
            "suspicious": suspicious,
            "severity": severity,
            "category": category,
            "demo": is_demo,
        }
        self._record(event)

    def _record(self, event):
        with self._lock:
            self.events.append(event)
            if event["ip"]:
                self.ip_counter[event["ip"]] += 1
            if event["host"] and event["host"] != "-":
                self.host_counter[event["host"]] += 1
            self.stats["total"] += 1
            if event["demo"]:
                self.stats["demo"] += 1
            else:
                self.stats["received"] += 1
            if event["suspicious"]:
                self.stats["suspicious"] += 1
            self.stats["last_event"] = event["timestamp"]

        self.socketio.emit("syslog_event", event)

        # 의심 + 외부 IP → 파이프라인 주입
        if event["suspicious"] and self._is_external(event["ip"]):
            self._escalate(event)

    def _escalate(self, event):
        if self.attack_map and event["severity"] in ("HIGH", "CRITICAL"):
            try:
                self.attack_map.add_attack_ip(event["ip"], "PORT_SCAN", event["severity"])
            except Exception:
                pass
        if self.mitre and event["severity"] in ("HIGH", "CRITICAL"):
            try:
                self.mitre.map_threat("ANOMALY", src_ip=event["ip"],
                                      description=f"[Syslog/{event['host']}] {event['category']}")
            except Exception:
                pass
        if self.threat_detector:
            try:
                ttype = _CATEGORY_THREAT.get(event["category"], "ANOMALY")
                self.threat_detector.report_alert(
                    ttype, event["severity"], event["ip"], self._server_ip,
                    f"[Syslog/{event['host']}] {event['category']}: {event['message'][:160]}",
                    {"source": "syslog", "host": event["host"], "tag": event["tag"],
                     "transport": event["transport"], "category": event["category"]})
            except Exception as e:
                _log.error(f"[Syslog] 알림 전달 오류: {e}")

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
    #  데모 fallback — KR/USA 가 보낼 법한 syslog 메시지 합성
    # ------------------------------------------------------------------ #

    _DEMO_HOSTS = ["kr-trader", "usa-trader"]
    _DEMO_MSGS = [
        '{ip} - - [{t}] "GET / HTTP/1.1" 200 -',
        '{ip} - - [{t}] "GET /.env HTTP/1.1" 404 -',
        '{ip} - - [{t}] "GET /wp-login.php HTTP/1.1" 404 -',
        '{ip} - - [{t}] "PRI * HTTP/2.0" 505 -',
        'sshd: Failed password for invalid user admin from {ip} port 51022',
        'dashboard: 403 Forbidden unauthorized access to /admin from {ip}',
        'waf: possible SQL injection detected: id=1 UNION SELECT from {ip}',
        'app: health check ok from {ip}',
    ]

    def _demo_loop(self):
        time.sleep(2)
        while self.running:
            ip = f"{random.randint(1,223)}.{random.randint(0,254)}." \
                 f"{random.randint(0,254)}.{random.randint(1,254)}"
            host = random.choice(self._DEMO_HOSTS)
            tmpl = random.choice(self._DEMO_MSGS)
            body = tmpl.format(ip=ip, t=datetime.now().strftime("%d/%b/%Y %H:%M:%S"))
            # RFC3164 형태로 합성 (<PRI>는 local0.info=134 예시)
            line = f"<134>{datetime.now().strftime('%b %d %H:%M:%S')} {host} {body}"
            self._handle(line, peer=ip, transport="demo", is_demo=True)
            time.sleep(random.uniform(3.0, 8.0))


# 분류 카테고리 → threat_detector 위협 유형
_CATEGORY_THREAT = {
    "인증 실패/무차별 대입": "BRUTE_FORCE",
    "SQL 인젝션 시도": "WEB_ATTACK",
    "XSS 시도": "WEB_ATTACK",
    "경로 탐색 시도": "WEB_ATTACK",
    "포트 스캔": "PORT_SCAN",
    "TLS 프로브 (HTTPS 스캔)": "PORT_SCAN",
    "바이너리 프로브 (프로토콜 스캔)": "PORT_SCAN",
    "HTTP/2 프로브": "PORT_SCAN",
    "악성코드/C2 의심": "MALWARE_BEACON",
}


def _clean(tok):
    return None if tok in (None, "-", "") else tok
