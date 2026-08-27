"""
SIEM 상관관계 분석 — 개별 알림(이벤트)들을 규칙으로 엮어 고신뢰 상관 탐지를 만든다.

킬체인(correlation.py)이 '한 IP의 알림들을 MITRE 전술 순서로 스토리화'하는 뷰라면,
이 모듈은 SIEM 상관 규칙(correlation rules)으로 **여러 신호를 결합해 새 알림을 발화**한다.
공통 chokepoint: threat_detector._add_alert → feed(alert) 로 유입.

규칙:
  R-MULTI-VECTOR   : 한 IP가 윈도우 내 서로 다른 위협유형 3종↑ → 다중벡터 공격 (HIGH/CRITICAL)
  R-RECON-INTRUSION: 정찰(PORT_SCAN/ANOMALY) 이후 침투(HONEYPOT/BRUTE_FORCE/WEB_ATTACK/C2) → CRITICAL
  R-SUSTAINED-BRUTE: 한 IP가 윈도우 내 BRUTE_FORCE 5회↑ → 지속적 무차별 대입 (HIGH)
  R-DISTRIBUTED    : 같은 위협유형을 서로 다른 IP 6개↑가 동시 발생 → 분산 공격 (HIGH)
  R-INTERNAL-EXFIL : 내부 호스트의 대량 외부 전송/DNS 터널링 → 자료 유출 의심 (CRITICAL)
  R-STAGING-EXFIL  : 수집·압축/엔드포인트 징후 후 외부 전송 → 내부자 유출 (CRITICAL)

발화 시 threat_detector.report_alert("CORRELATED", ...) 로 파이프라인에 재투입
(SOAR PB-CORRELATED-ESCALATE 로 인시던트 승격). 규칙별 (규칙,IP) 쿨다운으로 중복 억제.
"""
import time
import threading
from collections import deque, defaultdict

from modules.logging_setup import get_logger

_log = get_logger(__name__)

# 정찰/침투 위협 분류
_RECON = {"PORT_SCAN", "ANOMALY", "NETWORK_ANOMALY"}
_INTRUSION = {"HONEYPOT", "BRUTE_FORCE", "WEB_ATTACK", "MALWARE_BEACON", "EDR_THREAT", "SIGMA_MATCH"}
_EXFIL = {"DATA_EXFIL", "DNS_TUNNELING"}
_STAGING = {"EDR_THREAT", "SIGMA_MATCH", "ANOMALY"}


class SIEMCorrelator:
    def __init__(self, socketio, config=None, threat_detector=None):
        self.socketio = socketio
        self.config = config or {}
        self.threat_detector = threat_detector
        self.running = False
        self._lock = threading.Lock()

        self.window = float(self.config.get("SIEM_CORR_WINDOW", 600))     # 상관 윈도우(초)
        self.cooldown = float(self.config.get("SIEM_CORR_COOLDOWN", 300))  # 규칙별 재발화 간격
        self.multi_vector_min = int(self.config.get("SIEM_CORR_MULTIVECTOR", 3))
        self.brute_min = int(self.config.get("SIEM_CORR_BRUTE", 5))
        self.distributed_min = int(self.config.get("SIEM_CORR_DISTRIBUTED", 6))
        self.exfil_min_bytes = int(self.config.get("SIEM_EXFIL_MIN_BYTES", 500_000_000))

        self._by_ip = defaultdict(list)      # ip → [(ts, threat_type, severity)]
        self._by_type = defaultdict(list)    # threat_type → [(ts, ip)]
        self._fired = {}                     # (rule, key) → 마지막 발화 ts
        self.findings = deque(maxlen=300)
        self.stats = {"total": 0, "by_rule": defaultdict(int), "mode": "live"}

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        self.running = True
        _log.info("[SIEMCorr] 상관관계 분석 시작 — "
              f"윈도우 {int(self.window)}s · 다중벡터≥{self.multi_vector_min} · "
              f"브루트≥{self.brute_min} · 분산≥{self.distributed_min}")
        if demo:
            threading.Thread(target=self._demo_loop, daemon=True).start()

    def stop(self):
        self.running = False

    # 데모: 실 알림은 IP가 매번 랜덤이라 상관이 잘 안 엮여 시연용 시나리오를 주입
    def _demo_loop(self):
        import random
        scenarios = [
            [("PORT_SCAN", "HIGH"), ("BRUTE_FORCE", "HIGH"), ("HONEYPOT", "CRITICAL")],  # 정찰→침투+다중
            [("PORT_SCAN", "HIGH"), ("WEB_ATTACK", "HIGH"), ("MALWARE_BEACON", "CRITICAL")],
            [("BRUTE_FORCE", "HIGH")] * (self.brute_min + 1),                             # 지속 브루트
        ]
        time.sleep(8)
        while self.running:
            if random.random() < 0.55:
                ip = f"185.220.{random.randint(1,254)}.{random.randint(1,254)}"
                for t, sev in random.choice(scenarios):
                    if not self.running:
                        return
                    self.feed({"src_ip": ip, "threat_type": t, "severity": sev})
                    time.sleep(0.4)
            else:  # 분산 공격 시나리오
                for i in range(self.distributed_min + 1):
                    self.feed({"src_ip": f"45.155.{random.randint(1,254)}.{i}",
                               "threat_type": "PORT_SCAN", "severity": "HIGH"})
            time.sleep(random.uniform(12, 22))

    def get_stats(self):
        with self._lock:
            return {"total": self.stats["total"], "mode": "live",
                    "by_rule": dict(self.stats["by_rule"]),
                    "active_ips": len(self._by_ip)}

    def get_status(self):
        return {"stats": self.get_stats(),
                "rules": [
                    {"id": "R-MULTI-VECTOR", "name": "다중 벡터 공격",
                     "desc": f"한 IP가 서로 다른 위협유형 {self.multi_vector_min}종↑"},
                    {"id": "R-RECON-INTRUSION", "name": "정찰 후 침투",
                     "desc": "정찰(스캔) 이후 같은 IP의 침투 시도(허니팟·브루트·웹공격 등)"},
                    {"id": "R-SUSTAINED-BRUTE", "name": "지속 무차별 대입",
                     "desc": f"한 IP의 BRUTE_FORCE {self.brute_min}회↑"},
                    {"id": "R-DISTRIBUTED", "name": "분산 공격",
                     "desc": f"같은 위협유형을 서로 다른 IP {self.distributed_min}개↑ 동시"},
                    {"id": "R-INTERNAL-EXFIL", "name": "내부 자료 유출",
                     "desc": "내부 호스트의 대량 외부 전송 또는 DNS 터널링"},
                    {"id": "R-STAGING-EXFIL", "name": "수집·압축 후 유출",
                     "desc": "EDR/Sigma 수집 징후 이후 같은 호스트의 외부 전송"},
                ],
                "findings": list(reversed(list(self.findings)))[:100]}

    # ------------------------------------------------------------------ #
    #  유입 + 규칙 평가
    # ------------------------------------------------------------------ #

    def feed(self, alert):
        ip = alert.get("src_ip")
        ttype = alert.get("threat_type")
        sev = alert.get("severity", "MEDIUM")
        details = alert.get("details") or {}
        dst_ip = alert.get("dst_ip")
        if not ip or not ttype:
            return
        now = time.time()
        with self._lock:
            self._by_ip[ip].append((now, ttype, sev, details, dst_ip))
            self._by_type[ttype].append((now, ip))
            self._prune(now)
            hits = self._evaluate(ip, ttype, now, details, dst_ip)
        for f in hits:
            self._fire(f)

    def _prune(self, now):
        cut = now - self.window
        for ip in list(self._by_ip):
            self._by_ip[ip] = [x for x in self._by_ip[ip] if x[0] >= cut]
            if not self._by_ip[ip]:
                del self._by_ip[ip]
        for t in list(self._by_type):
            self._by_type[t] = [x for x in self._by_type[t] if x[0] >= cut]
            if not self._by_type[t]:
                del self._by_type[t]

    def _evaluate(self, ip, ttype, now, details=None, dst_ip=None):
        """윈도우 상태로 규칙 평가 → 발화 후보 리스트."""
        details = details or {}
        out = []
        events = self._by_ip.get(ip, [])
        types = {e[1] for e in events}

        # 내부 자료 유출: 탐지기가 이미 볼륨/외부 목적지를 검증한 DATA_EXFIL 또는
        # DNS 터널링. 내부 호스트를 자동 차단하지 않고 SOAR 조사 플레이북으로 넘긴다.
        if ttype in _EXFIL and self._is_internal(ip):
            bytes_out = int(details.get("bytes_in_window") or
                            details.get("bytes_per_5min") or 0)
            volume_ok = ttype == "DNS_TUNNELING" or bytes_out >= self.exfil_min_bytes
            if volume_ok:
                out.append({"rule": "R-INTERNAL-EXFIL", "key": ip, "ip": ip,
                            "severity": "CRITICAL", "dst_ip": dst_ip,
                            "summary": (f"내부 자료 유출 의심 — {ip} → {dst_ip or '외부'} · "
                                        f"{bytes_out / 1e6:.1f}MB" if bytes_out else
                                        f"DNS 터널링 기반 자료 유출 의심 — {ip}"),
                            "count": 1, "bytes_out": bytes_out,
                            "evidence": [ttype, "internal_to_external"]})

        if (types & _EXFIL) and (types & _STAGING) and self._is_internal(ip):
            out.append({"rule": "R-STAGING-EXFIL", "key": ip, "ip": ip,
                        "severity": "CRITICAL", "dst_ip": dst_ip,
                        "summary": f"수집·압축 징후({', '.join(sorted(types & _STAGING))}) 후 "
                                   f"외부 전송({', '.join(sorted(types & _EXFIL))})",
                        "count": len(events),
                        "evidence": sorted((types & _STAGING) | (types & _EXFIL))})

        # R-RECON-INTRUSION: 정찰 유형과 침투 유형이 같은 IP에 공존
        if (types & _RECON) and (types & _INTRUSION):
            out.append({"rule": "R-RECON-INTRUSION", "key": ip, "ip": ip,
                        "severity": "CRITICAL",
                        "summary": f"정찰({', '.join(sorted(types & _RECON))}) 후 "
                                   f"침투({', '.join(sorted(types & _INTRUSION))})",
                        "count": len(events)})

        # R-MULTI-VECTOR: 서로 다른 위협유형 N종 이상
        if len(types) >= self.multi_vector_min:
            sev = "CRITICAL" if (len(types) >= self.multi_vector_min + 1
                                 or types & _INTRUSION) else "HIGH"
            out.append({"rule": "R-MULTI-VECTOR", "key": ip, "ip": ip, "severity": sev,
                        "summary": f"다중 벡터 — {len(types)}종 위협: {', '.join(sorted(types))}",
                        "count": len(events)})

        # R-SUSTAINED-BRUTE: BRUTE_FORCE 반복
        brute = sum(1 for e in events if e[1] == "BRUTE_FORCE")
        if brute >= self.brute_min:
            out.append({"rule": "R-SUSTAINED-BRUTE", "key": ip, "ip": ip, "severity": "HIGH",
                        "summary": f"지속 무차별 대입 — {brute}회/{int(self.window/60)}분",
                        "count": brute})

        # R-DISTRIBUTED: 같은 유형을 여러 IP가 동시에
        ips = {x[1] for x in self._by_type.get(ttype, [])}
        if len(ips) >= self.distributed_min:
            out.append({"rule": "R-DISTRIBUTED", "key": ttype, "ip": "다수",
                        "severity": "HIGH",
                        "summary": f"분산 공격 — {ttype} 을(를) 서로 다른 IP {len(ips)}개가 동시 시도",
                        "count": len(ips), "sources": sorted(ips)[:12]})
        return out

    def _fire(self, f):
        key = (f["rule"], f["key"])
        now = time.time()
        with self._lock:
            if now - self._fired.get(key, 0) < self.cooldown:
                return
            self._fired[key] = now
            self.stats["total"] += 1
            self.stats["by_rule"][f["rule"]] += 1
            record = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                      "rule": f["rule"], "ip": f["ip"], "severity": f["severity"],
                      "summary": f["summary"], "count": f.get("count", 0),
                      "sources": f.get("sources"), "dst_ip": f.get("dst_ip"),
                      "bytes_out": f.get("bytes_out", 0),
                      "evidence": f.get("evidence", [])}
            self.findings.append(record)

        self.socketio.emit("siem_correlation", record)

        # 파이프라인 재투입 (분산공격은 대표 IP가 없어 report 생략, 표시만)
        if self.threat_detector and f["ip"] != "다수":
            try:
                self.threat_detector.report_alert(
                    "CORRELATED", f["severity"], f["ip"],
                    getattr(self.threat_detector, "_server_ip", "-"),
                    f"[상관관계/{f['rule']}] {f['summary']}",
                    {"source": "siem_correlation", "rule": f["rule"],
                     "count": f.get("count"), "dst_ip": f.get("dst_ip"),
                     "bytes_out": f.get("bytes_out", 0),
                     "evidence": f.get("evidence", [])})
            except Exception as e:
                _log.error(f"[SIEMCorr] 알림 전달 오류: {e}")

    @staticmethod
    def _is_internal(ip):
        if not ip:
            return False
        if (ip.startswith(("10.", "192.168.", "127.")) or
                any(ip.startswith(f"172.{n}.") for n in range(16, 32))):
            return True
        try:
            a, b = ip.split(".")[:2]
            return int(a) == 100 and 64 <= int(b) <= 127
        except (ValueError, IndexError):
            return False
