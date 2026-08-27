"""
SSH 인증 로그 실시간 탐지 모듈 (실제 침해 시도 관제)

/var/log/auth.log (또는 지정 경로)를 tail 하여 sshd 로그인 시도를 파싱한다.
- 로그인 성공/실패/무효 사용자 이벤트를 실시간 스트림으로 노출
- 동일 IP의 실패가 임계값(기본 5회/120초)을 넘으면 threat_detector 로
  BRUTE_FORCE 알림 전달 → 전체 파이프라인(신뢰도→AI 트리아지→SOAR 차단→인시던트) 자동 연동

로그 파일이 없거나 권한이 없으면 데모 fallback (CLAUDE.md 규칙).
"""
import os
import re
import time
import socket
import random
import threading
from datetime import datetime
from collections import deque, defaultdict, Counter

from modules.logging_setup import get_logger

_log = get_logger(__name__)

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
# OpenSSH 표준 로그 패턴
_RE_FAILED = re.compile(r"Failed (?:password|publickey) for (invalid user )?(\S+) from " + _IP + r" port (\d+)")
_RE_INVALID = re.compile(r"Invalid user (\S+) from " + _IP)
_RE_PREAUTH = re.compile(r"(?:Connection closed by|Disconnected from) (?:authenticating|invalid) user (\S+) " + _IP)
_RE_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from " + _IP + r" port (\d+)")


class AuthLogMonitor:
    def __init__(self, socketio, config=None, threat_detector=None,
                 log_path="/var/log/auth.log"):
        self.socketio = socketio
        self.config = config or {}
        self.threat_detector = threat_detector
        self.log_path = self.config.get("AUTH_LOG_PATH") or log_path
        self.running = False
        self._lock = threading.Lock()

        self.threshold = int(self.config.get("SSH_BRUTE_THRESHOLD", 5))
        self.window = float(self.config.get("SSH_BRUTE_WINDOW", 120))
        self.cooldown = 300.0        # 동일 IP 재알림 최소 간격

        self.events = deque(maxlen=500)
        self._fail_window = defaultdict(list)   # ip → [실패 ts]
        self._alerted = {}                       # ip → 마지막 알림 ts
        self._ip_counter = Counter()
        self.stats = {
            "total": 0, "failed": 0, "invalid": 0, "accepted": 0,
            "brute_alerts": 0, "unique_ips": 0, "mode": "-",
        }
        self._server_ip = self._detect_server_ip()

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        if os.path.exists(self.log_path) and os.access(self.log_path, os.R_OK):
            self.stats["mode"] = "real"
            _log.info(f"[AuthLog] 실시간 SSH 인증 로그 감시 시작: {self.log_path}")
            threading.Thread(target=self._tail_loop, daemon=True).start()
        elif demo:
            self.stats["mode"] = "demo"
            _log.warning(f"[AuthLog] {self.log_path} 접근 불가 — 데모 모드")
            threading.Thread(target=self._demo_loop, daemon=True).start()
        else:
            self.stats["mode"] = "off"
            _log.warning(f"[AuthLog] {self.log_path} 접근 불가 — 비활성")

    def stop(self):
        self.running = False

    def get_events(self, limit=100, suspicious_only=False):
        with self._lock:
            evs = list(self.events)
        if suspicious_only:
            evs = [e for e in evs if e["type"] in ("failed", "invalid", "preauth")]
        return list(reversed(evs))[:limit]

    def get_status(self):
        with self._lock:
            stats = dict(self.stats)
            stats["unique_ips"] = len(self._ip_counter)
            stats["top_ips"] = self._ip_counter.most_common(10)
        return {"stats": stats, "events": self.get_events(80)}

    # ------------------------------------------------------------------ #
    #  실시간 tail
    # ------------------------------------------------------------------ #

    def _tail_loop(self):
        offset = os.path.getsize(self.log_path)   # 기존 로그는 건너뛰고 새 줄만
        while self.running:
            try:
                size = os.path.getsize(self.log_path)
                if size < offset:      # 로테이션 감지 → 처음부터
                    offset = 0
                if size > offset:
                    with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(offset)
                        chunk = f.read()
                        offset = f.tell()
                    for line in chunk.splitlines():
                        if "sshd" in line:
                            self._process_line(line)
            except FileNotFoundError:
                offset = 0
            except Exception as e:
                _log.error(f"[AuthLog] tail 오류: {e}")
            time.sleep(1.0)

    def _process_line(self, line):
        m = _RE_FAILED.search(line)
        if m:
            invalid, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
            self._record(ip, user, "invalid" if invalid else "failed", int(port), line)
            self._track_failure(ip, user)
            return
        m = _RE_INVALID.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            self._record(ip, user, "invalid", None, line)
            self._track_failure(ip, user)
            return
        m = _RE_PREAUTH.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            self._record(ip, user, "preauth", None, line)
            self._track_failure(ip, user)
            return
        m = _RE_ACCEPT.search(line)
        if m:
            method, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
            self._record(ip, user, "accepted", int(port), line, method=method)
            return

    # ------------------------------------------------------------------ #

    def _record(self, ip, user, ev_type, port, raw, method=None):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event = {
            "ip": ip, "user": user, "type": ev_type, "port": port,
            "method": method, "timestamp": ts,
        }
        with self._lock:
            self.events.append(event)
            self._ip_counter[ip] += 1
            self.stats["total"] += 1
            if ev_type == "accepted":
                self.stats["accepted"] += 1
            elif ev_type == "invalid":
                self.stats["invalid"] += 1
            else:
                self.stats["failed"] += 1
        self.socketio.emit("auth_event", event)

    def _track_failure(self, ip, user):
        """실패 누적 → 임계 초과 시 브루트포스 알림 (내부 IP 제외)"""
        if self._is_internal(ip):
            return
        now = time.time()
        with self._lock:
            win = [t for t in self._fail_window[ip] if now - t < self.window]
            win.append(now)
            self._fail_window[ip] = win
            count = len(win)
            last = self._alerted.get(ip, 0)
            if count >= self.threshold and now - last >= self.cooldown:
                self._alerted[ip] = now
                self.stats["brute_alerts"] += 1
                fire = True
            else:
                fire = False

        if fire and self.threat_detector:
            try:
                self.threat_detector.report_alert(
                    "BRUTE_FORCE", "HIGH", ip, self._server_ip,
                    f"SSH 무차별 대입: {ip} → {count}회 실패/{int(self.window)}초 (대상 계정: {user})",
                    {"fail_count": count, "window_s": int(self.window),
                     "last_user": user, "source": "auth.log",
                     "evidence": ["auth_bruteforce"], "demo": False})
            except Exception as e:
                _log.error(f"[AuthLog] 알림 전달 오류: {e}")

    # ------------------------------------------------------------------ #

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

    _PRIVATE = ("10.", "127.", "192.168.", "169.254.",
                "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

    @classmethod
    def _is_internal(cls, ip):
        # 사설 + Tailscale/CGNAT(100.64/10) 는 브루트포스 집계 제외
        if ip.startswith(cls._PRIVATE):
            return True
        try:
            a, b = ip.split(".")[:2]
            return int(a) == 100 and 64 <= int(b) <= 127
        except (ValueError, IndexError):
            return False

    # ------------------------------------------------------------------ #
    #  데모 fallback
    # ------------------------------------------------------------------ #

    _DEMO_USERS = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "git", "user"]

    def _demo_loop(self):
        time.sleep(2)
        while self.running:
            # 가끔 브루트포스 시나리오: 한 IP가 연속 실패
            ip = f"{random.randint(1,223)}.{random.randint(0,254)}." \
                 f"{random.randint(0,254)}.{random.randint(1,254)}"
            if random.random() < 0.35:
                for _ in range(random.randint(5, 9)):
                    if not self.running:
                        return
                    self._record(ip, random.choice(self._DEMO_USERS),
                                 random.choice(["failed", "invalid"]), 22, "demo")
                    self._track_failure(ip, random.choice(self._DEMO_USERS))
                    time.sleep(random.uniform(0.3, 1.2))
            else:
                self._record(ip, random.choice(self._DEMO_USERS),
                             random.choice(["failed", "invalid"]), 22, "demo")
                self._track_failure(ip, "root")
            time.sleep(random.uniform(4.0, 10.0))
