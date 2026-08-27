"""
위협 탐지 모듈
- DDoS 탐지 (패킷/초 임계값)
- 포트 스캔 탐지
- 비정상 트래픽 탐지
- Scapy 기반 능동 스캔 지원
"""
import threading
import time
import random
from datetime import datetime
from collections import defaultdict, deque

from modules.alert_store import AlertStore


SEVERITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

THREAT_TYPES = {
    "DDOS": "DDoS 공격",
    "PORT_SCAN": "포트 스캔",
    "BRUTE_FORCE": "무차별 대입 공격",
    "MALWARE_BEACON": "악성코드 C2 통신",
    "DATA_EXFIL": "데이터 유출 의심",
    "ARP_SPOOFING": "ARP 스푸핑",
    "DNS_TUNNELING": "DNS 터널링",
    "ANOMALY": "이상 트래픽",
    "EDR_THREAT": "EDR 엔드포인트 위협",
    "NETWORK_ANOMALY": "네트워크 이상",
    "SIGMA_MATCH": "Sigma 룰 탐지",
    "WEB_ATTACK": "웹 공격 (SQLi/XSS 등)",
    "HONEYPOT": "허니팟 유인 탐지",
    "CORRELATED": "SIEM 상관관계 탐지",
    "SNORT_ALERT": "Snort IDS 탐지",
}


class Alert:
    _id_counter = 0
    _id_lock = threading.Lock()

    def __init__(self, threat_type, severity, src_ip, dst_ip, description, details=None):
        with Alert._id_lock:
            Alert._id_counter += 1
            self.id = Alert._id_counter
        self.threat_type = threat_type
        self.severity = severity
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.description = description
        self.details = details or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status = "OPEN"  # OPEN / ACK / CLOSED
        self.note = ""
        self.assignee = ""
        self.origin = "demo" if self.details.get("demo") else "real"
        self.verdict = "UNREVIEWED"
        self.verdict_actor = ""
        self.verdict_reason = ""
        self.verdict_at = ""

    def to_dict(self):
        return {
            "id": self.id,
            "threat_type": self.threat_type,
            "threat_label": THREAT_TYPES.get(self.threat_type, self.threat_type),
            "severity": self.severity,
            "severity_level": SEVERITY.get(self.severity, 0),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "description": self.description,
            "details": self.details,
            "timestamp": self.timestamp,
            "status": self.status,
            "note": self.note,
            "assignee": self.assignee,
            "origin": self.origin,
            "verdict": self.verdict,
            "verdict_actor": self.verdict_actor,
            "verdict_reason": self.verdict_reason,
            "verdict_at": self.verdict_at,
            "confidence": getattr(self, "confidence", None),
        }


_STATUS_STAT_KEY = {"OPEN": "open", "ACK": "acknowledged", "CLOSED": "closed"}


class ThreatDetector:
    def __init__(self, socketio, config=None, mitre_tracker=None,
                 attack_map=None, store_path="data/alerts.db"):
        self.socketio = socketio
        self.config = config
        self.mitre = mitre_tracker
        self.attack_map = attack_map
        self.threat_intel = None   # app.py 에서 주입 (IoC 기반 신뢰도 가중)
        self.ip_reputation = None  # app.py 에서 주입 (AbuseIPDB 평판 신뢰도 가중)
        self.soar = None           # app.py 에서 주입 (자동 대응 플레이북)
        self.dedup = None          # wiring.py 에서 주입 (중복제거·억제 레이어)
        self.decision = None       # app.py 에서 주입 (ML 의사결정 지원)
        self.watchlist = None      # wiring 에서 주입 (IOC 워치리스트 대조)
        self.siem_correlator = None  # wiring 에서 주입 (SIEM 상관관계 분석)
        self.running = False

        # 정탐 신뢰도 임계값 — 미만이면 '오탐 의심'으로 저장만 하고 emit 억제
        try:
            self.min_confidence = float(
                (config or {}).get("ALERT_CONFIDENCE_THRESHOLD", 0.5))
        except (TypeError, ValueError):
            self.min_confidence = 0.5
        try:
            self.exfil_bytes_threshold = max(1, int(
                (config or {}).get("DATA_EXFIL_BYTES_THRESHOLD", 500_000_000)))
            self.exfil_window_seconds = max(10, int(
                (config or {}).get("DATA_EXFIL_WINDOW_SECONDS", 300)))
        except (TypeError, ValueError):
            self.exfil_bytes_threshold, self.exfil_window_seconds = 500_000_000, 300
        allow = str((config or {}).get("DATA_EXFIL_ALLOWLIST", "") or "")
        self.exfil_allowlist = tuple(x.strip() for x in allow.split(",") if x.strip())

        self.alerts = deque(maxlen=500)
        self.alert_counts = defaultdict(int)
        self._lock = threading.Lock()
        self._win_lock = threading.Lock()

        # 탐지 상태
        self._ip_packet_window = defaultdict(list)   # IP → [timestamps]
        self._ip_port_window = defaultdict(set)      # IP → {(port, ts)}
        self._ip_byte_window = defaultdict(list)     # IP → [(ts, bytes)]

        # 통계
        self.stats = {
            "total_alerts": 0,
            "deduplicated": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "open": 0,
            "acknowledged": 0,
            "closed": 0,
            "suppressed": 0,   # 오탐 의심으로 emit 억제된 수
        }

        # 영속화: 이전 세션 알림 복원
        self.store = None
        if store_path:
            try:
                self.store = AlertStore(store_path)
                self._restore_alerts()
            except Exception as e:
                print(f"[ThreatDetector] 알림 DB 초기화 실패: {e}")
                self.store = None

    def _restore_alerts(self):
        for row in self.store.load_recent(500):
            alert = Alert.__new__(Alert)
            alert.id = row["id"]
            alert.threat_type = row["threat_type"]
            alert.severity = row["severity"]
            alert.src_ip = row["src_ip"]
            alert.dst_ip = row["dst_ip"]
            alert.description = row["description"]
            alert.details = row["details"]
            alert.timestamp = row["timestamp"]
            alert.status = row["status"]
            alert.note = row["note"]
            alert.assignee = row["assignee"]
            alert.origin = row.get("origin", "unknown")
            alert.verdict = row.get("verdict", "UNREVIEWED")
            alert.verdict_actor = row.get("verdict_actor", "")
            alert.verdict_reason = row.get("verdict_reason", "")
            alert.verdict_at = row.get("verdict_at", "")
            details = row["details"] if isinstance(row["details"], dict) else {}
            alert.confidence = details.get("confidence")
            self.alerts.append(alert)
            self.stats["total_alerts"] += 1
            sev_key = (alert.severity or "").lower()
            if sev_key in self.stats:
                self.stats[sev_key] += 1
            stat_key = _STATUS_STAT_KEY.get(alert.status, "open")
            self.stats[stat_key] += 1
        with Alert._id_lock:
            Alert._id_counter = max(Alert._id_counter, self.store.max_id())

    # ------------------------------------------------------------------ #
    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        if demo:
            threading.Thread(target=self._demo_loop, daemon=True).start()
        threading.Thread(target=self._emit_loop, daemon=True).start()

    def stop(self):
        self.running = False

    # ------------------------------------------------------------------ #
    #  외부 로그 소스가 탐지한 위협을 파이프라인에 주입
    # ------------------------------------------------------------------ #

    def report_alert(self, threat_type, severity, src_ip, dst_ip,
                     description, details=None):
        """auth.log 등 외부 파서가 탐지한 위협을 알림으로 등록.
        신뢰도 산정·중복억제·AI 트리아지·SOAR·인시던트까지 자동 연동된다."""
        self._add_alert(Alert(threat_type, severity, src_ip, dst_ip,
                              description, details))

    # ------------------------------------------------------------------ #
    #  실시간 패킷 기반 탐지 (packet_analyzer 와 연동)
    # ------------------------------------------------------------------ #

    def analyze_packet(self, src_ip, dst_ip, dst_port, proto, length):
        """
        FP 완화: 임계값 상향 + 3초 지속 + IP 신뢰목록(화이트리스트) 적용
        """
        now = time.time()

        # 내부/신뢰 IP는 DDoS·스캔에서만 제외한다. 내부→외부 유출 집계는 계속한다.
        src_internal = self._is_internal(src_ip)
        src_trusted = self._is_trusted(src_ip) or src_internal

        with self._win_lock:
            # ── DDoS: 3초 동안 지속적으로 2000pps 초과해야 경보 ──
            avg_pps, ddos_hit = 0, False
            if not src_trusted:
                self._ip_packet_window[src_ip].append(now)
                self._ip_packet_window[src_ip] = [
                    t for t in self._ip_packet_window[src_ip] if now - t < 3.0
                ]
                avg_pps = len(self._ip_packet_window[src_ip]) / 3.0
                ddos_hit = avg_pps > 2000
            if ddos_hit:
                # 쿨다운: 윈도우 비워서 재탐지 지연
                self._ip_packet_window[src_ip].clear()

            # ── 포트 스캔: 30초 동안 고유 포트 40개 이상 + 저바이트 트래픽 ──
            scan_hit = False
            unique_ports = 0
            if not src_trusted and dst_port and length < 200:
                self._ip_port_window[src_ip].add((dst_port, now))
                # 30초 이내 항목만 유지
                self._ip_port_window[src_ip] = {
                    (p, t) for (p, t) in self._ip_port_window[src_ip] if now - t < 30
                }
                unique_ports = len({p for (p, _) in self._ip_port_window[src_ip]})
                scan_hit = unique_ports >= 40
                if scan_hit:
                    self._ip_port_window[src_ip].clear()

            # ── 데이터 유출: 설정 윈도우 내 대량 전송 + 외부/비허용 목적지 ──
            exfil_hit = False
            total_bytes = 0
            approved_dst = any(dst_ip == x or (x.endswith(".") and dst_ip.startswith(x))
                               for x in self.exfil_allowlist) if dst_ip else False
            if (src_internal and self._is_external(dst_ip) and not approved_dst):
                self._ip_byte_window[src_ip].append((now, length))
                self._ip_byte_window[src_ip] = [
                    (t, b) for t, b in self._ip_byte_window[src_ip]
                    if now - t < self.exfil_window_seconds
                ]
                total_bytes = sum(b for _, b in self._ip_byte_window[src_ip])
                exfil_hit = total_bytes > self.exfil_bytes_threshold
                if exfil_hit:
                    self._ip_byte_window[src_ip].clear()

        if ddos_hit:
            self._add_alert(Alert(
                "DDOS", "CRITICAL", src_ip, dst_ip,
                f"DDoS 의심(3초 평균): {src_ip} → {avg_pps:.0f} pkt/s 지속",
                {"pps_avg_3s": round(avg_pps, 1)},
            ))
        if scan_hit:
            self._add_alert(Alert(
                "PORT_SCAN", "HIGH", src_ip, dst_ip,
                f"포트 스캔: {src_ip} → {unique_ports}개 포트/30초",
                {"ports_scanned": unique_ports},
            ))
        if exfil_hit:
            self._add_alert(Alert(
                "DATA_EXFIL",
                "CRITICAL" if total_bytes >= self.exfil_bytes_threshold * 2 else "HIGH",
                src_ip, dst_ip,
                f"내부 자료 유출 의심: {src_ip} → {dst_ip} · "
                f"{total_bytes / 1e6:.1f} MB/{self.exfil_window_seconds // 60}분",
                {"bytes_in_window": total_bytes,
                 "window_seconds": self.exfil_window_seconds,
                 "threshold_bytes": self.exfil_bytes_threshold,
                 "direction": "internal_to_external", "source": "packet_sensor",
                 "evidence": ["high_volume_egress"], "demo": False},
            ))

    def _prune_windows(self):
        """오래 조용한 IP 항목 제거 — 랜덤/스푸핑 IP로 인한 무한 증가 방지."""
        now = time.time()
        with self._win_lock:
            for win, horizon in ((self._ip_packet_window, 10),
                                 (self._ip_byte_window, 360)):
                stale = [ip for ip, entries in win.items()
                         if not entries or now - self._last_ts(entries) > horizon]
                for ip in stale:
                    del win[ip]
            stale = [ip for ip, entries in self._ip_port_window.items()
                     if not entries or now - max(t for _, t in entries) > 60]
            for ip in stale:
                del self._ip_port_window[ip]

    @staticmethod
    def _last_ts(entries):
        last = entries[-1]
        return last[0] if isinstance(last, tuple) else last

    # ── IP 판별 헬퍼 ───────────────────────────────────────
    _TRUSTED_PREFIXES = ("127.", "169.254.", "224.", "239.", "255.255.255.")
    _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.",
                         "172.24.", "172.25.", "172.26.", "172.27.",
                         "172.28.", "172.29.", "172.30.", "172.31.",
                         "192.168.")

    def _is_trusted(self, ip):
        if not ip:
            return True
        return ip.startswith(self._TRUSTED_PREFIXES)

    def _is_external(self, ip):
        if not ip:
            return False
        if ip.startswith(self._TRUSTED_PREFIXES):
            return False
        if ip.startswith(self._PRIVATE_PREFIXES):
            return False
        return True

    def _is_internal(self, ip):
        if not ip:
            return False
        if ip.startswith(self._PRIVATE_PREFIXES):
            return True
        try:
            a, b = ip.split(".")[:2]
            return int(a) == 100 and 64 <= int(b) <= 127
        except (ValueError, IndexError):
            return False

    def update_alert_status(self, alert_id, status, note=None, assignee=None):
        with self._lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    old_key = _STATUS_STAT_KEY.get(alert.status, "open")
                    new_key = _STATUS_STAT_KEY.get(status, "open")
                    alert.status = status
                    if note is not None:
                        alert.note = note
                    if assignee is not None:
                        alert.assignee = assignee
                    self.stats[old_key] = max(0, self.stats.get(old_key, 0) - 1)
                    self.stats[new_key] = self.stats.get(new_key, 0) + 1
                    if self.store:
                        try:
                            self.store.update_status(alert_id, status, note, assignee)
                        except Exception:
                            pass
                    return True
        return False

    def enrich_alert(self, alert_id, details):
        """외부 위협 인텔 결과를 메모리와 영속 알림에 병합한다."""
        found = False
        with self._lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.details.update(details or {})
                    found = True
                    break
        if self.store:
            try:
                found = self.store.update_details(alert_id, details) or found
            except Exception:
                pass
        return found

    def set_alert_verdict(self, alert_id, verdict, actor, reason=""):
        from datetime import datetime
        decided_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        found = False
        with self._lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.verdict, alert.verdict_actor = verdict, actor
                    alert.verdict_reason, alert.verdict_at = reason, decided_at
                    found = True
                    break
        if self.store:
            found = self.store.set_verdict(alert_id, verdict, actor, reason, decided_at) or found
        if found and self.decision and verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            self.decision.record_verdict(alert_id, verdict == "TRUE_POSITIVE", source="분석가")
        return found

    def get_alerts(self, limit=100, severity=None, status=None):
        with self._lock:
            result = list(self.alerts)
        if severity:
            result = [a for a in result if a.severity == severity]
        if status:
            result = [a for a in result if a.status == status]
        return [a.to_dict() for a in reversed(result)][:limit]

    def search_alerts(self, **filters):
        """전체 DB 이력 검색 (threat_label 부가). (rows, total) 반환.
        DB 미사용(store=None) 시 in-memory 폴백."""
        if self.store:
            rows, total = self.store.search(**filters)
        else:
            rows = self.get_alerts(limit=filters.get("limit", 100),
                                   severity=filters.get("severity"),
                                   status=filters.get("status"))
            total = len(rows)
        for r in rows:
            r["threat_label"] = THREAT_TYPES.get(r["threat_type"], r["threat_type"])
        return rows, total

    def threat_type_labels(self):
        return dict(THREAT_TYPES)

    def get_stats(self):
        with self._lock:
            return dict(self.stats)

    # ------------------------------------------------------------------ #
    #  SocketIO emit 루프
    # ------------------------------------------------------------------ #

    def _emit_loop(self):
        while self.running:
            self._prune_windows()
            with self._lock:
                payload = {
                    "stats": dict(self.stats),
                    "recent_alerts": [a.to_dict() for a in list(self.alerts)[-10:]],
                }
            self.socketio.emit("threat_update", payload)
            time.sleep(5)

    # ------------------------------------------------------------------ #
    #  내부
    # ------------------------------------------------------------------ #

    # 심각도별 기본 신뢰도
    _BASE_CONFIDENCE = {"CRITICAL": 0.75, "HIGH": 0.65, "MEDIUM": 0.50, "LOW": 0.35}

    def _confidence(self, alert):
        """정탐 확률 추정 (0.05~0.99) — IoC 일치·재범 IP·외부 IP 가중"""
        score = self._BASE_CONFIDENCE.get(alert.severity, 0.5)
        evidence = set(alert.details.get("evidence") or [])
        if alert.details.get("source") == "snort":
            evidence.add("snort_signature")
            # 룰 우선순위는 강한 탐지 근거지만 단독 정탐 확정은 아니다.
            score += 0.10 if alert.details.get("priority") == 1 else 0.05

        # 위협 인텔 IoC 일치 → 사실상 정탐
        if self.threat_intel and alert.src_ip:
            try:
                if self.threat_intel.check_ip(alert.src_ip):
                    evidence.add("threat_intel_ioc")
                    alert.details["evidence"] = sorted(evidence)
                    return 0.98
            except Exception:
                pass

        # 외부 출발지는 가중, 내부↔내부 저심각도는 감점 (오탐 주범)
        if self._is_external(alert.src_ip):
            score += 0.10
        elif alert.severity in ("MEDIUM", "LOW"):
            score -= 0.15

        # IP 평판(AbuseIPDB): 전 세계 신고 점수로 정탐/오탐 근거 강화
        if self.ip_reputation and self._is_external(alert.src_ip):
            try:
                rep = self.ip_reputation.check(alert.src_ip)
                alert.details["ip_reputation"] = rep
                rscore = rep.get("score", 0)
                if rscore >= 90:        # 확실한 악성 → 사실상 정탐
                    evidence.add("abuseipdb_90")
                    alert.details["evidence"] = sorted(evidence)
                    return 0.97
                elif rscore >= self.ip_reputation.min_score:
                    evidence.add("abuseipdb_high")
                    score += 0.20       # 악성 신고 다수 → 강한 정탐 신호
                elif rscore >= 25:
                    score += 0.08
                elif rep.get("source") != "internal" and rscore == 0:
                    score -= 0.05       # 깨끗한 IP → 오탐 가능성 소폭 ↑
            except Exception:
                pass

        # 재범 IP: 최근 알림 이력에 같은 출발지가 있으면 가중
        with self._lock:
            repeats = sum(1 for a in list(self.alerts)[-100:]
                          if a.src_ip == alert.src_ip)
        score += min(0.15, repeats * 0.05)

        # ML 의사결정 지원: 같은 위협 그룹의 과거 정탐률(prior)과 혼합
        # → 오탐 반복 그룹은 신뢰도가 자동으로 내려가고, 정탐 그룹은 올라감
        if self.decision:
            try:
                prior = self.decision.cluster_prior(alert.threat_type, alert.src_ip)
                if prior:
                    rate, n = prior
                    weight = min(0.5, n * 0.1)   # 판정 누적될수록 prior 가중 ↑
                    score = (1 - weight) * score + weight * rate
            except Exception:
                pass

        alert.details["evidence"] = sorted(evidence)
        return max(0.05, min(0.99, round(score, 2)))

    # ------------------------------------------------------------------ #
    #  중복제거 · 억제 (modules/alert_dedup.py)
    # ------------------------------------------------------------------ #

    def _dedup_evaluate(self, alert):
        """dedup 레이어 판정. 레이어가 없거나 실패하면 통과시킨다.

        중복제거가 깨졌을 때 알림이 사라지는 것보다 중복이 나오는 편이 안전하다.
        """
        if not self.dedup:
            return {"action": "pass", "fingerprint": "", "count": 1,
                    "parent_id": None, "reason": "dedup 미설정"}
        try:
            return self.dedup.evaluate(alert.to_dict())
        except Exception as e:
            print(f"[ThreatDetector] dedup 판정 실패({e}) — 알림을 통과시킴")
            return {"action": "pass", "fingerprint": "", "count": 1,
                    "parent_id": None, "reason": f"dedup 오류: {type(e).__name__}"}

    def _handle_deduplicated(self, alert, verdict):
        """병합·억제된 알림을 처리한다. 원문은 이미 dedup 이 보관했다.

        새 알림을 만들지 않는 대신 기존 알림의 count/last_seen 을 올리고
        UI 에 갱신 이벤트를 보낸다. 어떤 경우에도 조용히 사라지지 않는다.
        """
        with self._lock:
            key = "suppressed" if verdict["action"] == "suppress" else "deduplicated"
            self.stats[key] = self.stats.get(key, 0) + 1

        parent_id = verdict.get("parent_id")
        if verdict["action"] != "duplicate" or parent_id is None:
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {"fingerprint": verdict["fingerprint"], "count": verdict["count"],
                   "last_seen": now}

        # 메모리 상의 알림 갱신
        with self._lock:
            for existing in reversed(self.alerts):
                if existing.id == parent_id:
                    info = existing.details.setdefault("dedup", {})
                    info.update(payload)
                    info.setdefault("first_seen", existing.timestamp)
                    break

        # 영속 갱신
        if self.store:
            try:
                self.store.update_details(parent_id, {"dedup": payload})
            except Exception:
                pass

        self.socketio.emit("alert_dedup", {
            "alert_id": parent_id, "count": verdict["count"],
            "last_seen": now, "reason": verdict["reason"],
            "fingerprint": verdict["fingerprint"],
        })

    def _add_alert(self, alert):
        alert.confidence = self._confidence(alert)
        alert.details["confidence"] = alert.confidence
        low_conf = alert.confidence < self.min_confidence
        if low_conf:
            alert.details["low_confidence"] = True

        # IOC 워치리스트 대조: 분석가가 주시 중인 지표면 알림에 표식
        if self.watchlist:
            try:
                wl_hits = self.watchlist.match_alert(alert.src_ip, alert.dst_ip)
                if wl_hits:
                    alert.details["watchlist"] = wl_hits
            except Exception:
                pass

        # 의사결정 지원: 모든 알림(오탐 의심 포함)을 위협 그룹에 반영
        if self.decision:
            try:
                self.decision.observe_alert(alert.to_dict())
            except Exception:
                pass

        # 중복제거·억제 레이어 (modules/alert_dedup.py)
        # 이전 구현은 같은 유형+IP 가 60초 내 OPEN 이면 조용히 drop 했다 —
        # 카운트도 기록도 없어 잘못 억제한 것을 되짚을 수 없었다.
        verdict = self._dedup_evaluate(alert)
        if verdict["action"] in ("duplicate", "suppress"):
            self._handle_deduplicated(alert, verdict)
            return
        alert.details["dedup"] = {
            "fingerprint": verdict["fingerprint"], "count": 1,
            "first_seen": alert.timestamp, "last_seen": alert.timestamp,
        }
        if verdict["action"] == "storm":
            alert.details["dedup"]["storm"] = True
            alert.details["dedup"]["count"] = verdict["count"]
            alert.description = f"[스톰] {alert.description}"

        with self._lock:
            self.alerts.append(alert)
            self.stats["total_alerts"] += 1
            sev_key = alert.severity.lower()
            self.stats[sev_key] = self.stats.get(sev_key, 0) + 1
            self.stats["open"] = self.stats.get("open", 0) + 1
            if low_conf:
                self.stats["suppressed"] += 1

        # 영속화 (오탐 의심 포함 — 나중에 검토 가능)
        if self.store:
            try:
                self.store.save(alert)
            except Exception:
                pass

        # 이후 같은 핑거프린트의 재발이 이 알림으로 병합되도록 id 를 확정한다
        if self.dedup:
            try:
                self.dedup.note_alert_id(verdict["fingerprint"], alert.id)
            except Exception:
                pass

        # 오탐 의심: 저장만 하고 실시간 emit·지도·MITRE 반영은 억제
        if low_conf:
            return

        self.socketio.emit("new_alert", alert.to_dict())

        # 공격 지도: 외부 출발지 IP만 GeoIP 조회 대상
        if self.attack_map and self._is_external(alert.src_ip):
            try:
                self.attack_map.add_attack_ip(
                    alert.src_ip, alert.threat_type, alert.severity
                )
            except Exception:
                pass

        # MITRE ATT&CK 매핑
        if self.mitre:
            try:
                self.mitre.map_threat(
                    alert.threat_type, alert.src_ip, alert.dst_ip, alert.description
                )
            except Exception:
                pass

        # SOAR 자동 대응 (고신뢰 알림만 도달)
        if self.soar:
            try:
                self.soar.handle_alert(alert.to_dict())
            except Exception:
                pass

        # SIEM 상관관계 분석 (CORRELATED 자신은 재투입 금지 → 무한루프 방지)
        if self.siem_correlator and alert.threat_type != "CORRELATED":
            try:
                self.siem_correlator.feed(alert.to_dict())
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    #  Demo 루프
    # ------------------------------------------------------------------ #

    # (threat_type, severity, src_template, dst_template, description, weight)
    _DEMO_THREATS = [
        ("DDOS",          "CRITICAL", "203.0.113.{}", "192.168.1.10",  "DDoS SYN Flood 탐지(pps > 2000 지속)", 1),
        ("PORT_SCAN",     "HIGH",     "198.51.100.{}", "192.168.1.0/24", "내부 네트워크 포트 스캔(40+ 포트/30초)", 2),
        ("BRUTE_FORCE",   "HIGH",     "185.220.{}.{}", "192.168.1.5",   "SSH 무차별 대입(실패 50+회/분)", 2),
        ("MALWARE_BEACON","CRITICAL", "192.168.1.{}", "45.33.{}.{}",   "알려진 C2 IP로 주기적 비콘 탐지", 1),
        ("ARP_SPOOFING",  "MEDIUM",   "192.168.1.{}", "192.168.1.1",   "ARP 스푸핑 — 게이트웨이 위장", 1),
        ("DNS_TUNNELING", "MEDIUM",   "192.168.1.{}", "8.8.8.8",       "비정상 길이 DNS 쿼리 다수(터널링 의심)", 1),
        ("DATA_EXFIL",    "HIGH",     "192.168.1.{}", "203.0.113.{}",  "외부 대량 전송(500MB+/5분)", 1),
    ]
    # ANOMALY (LOW) 는 FP 많아 demo에서 제거

    def _rand_ip(self, template):
        return template.format(*[random.randint(1, 254)
                                  for _ in range(template.count("{}"))])

    def _demo_loop(self):
        time.sleep(2)
        # 초기에 CRITICAL 1건 + HIGH 1건만 생성
        self._demo_create_random_alert()
        time.sleep(1.5)
        self._demo_create_random_alert()

        while self.running:
            # 주기 완화: 15-40초
            interval = random.uniform(15, 40)
            time.sleep(interval)
            # 60% 확률로만 발생
            if random.random() < 0.60:
                self._demo_create_random_alert()

    def _demo_create_random_alert(self):
        weights = [row[5] for row in self._DEMO_THREATS]
        choice  = random.choices(self._DEMO_THREATS, weights=weights, k=1)[0]
        ttype, sev, src_t, dst_t, desc, _ = choice
        src = self._rand_ip(src_t)
        dst = self._rand_ip(dst_t) if "{}" in dst_t else dst_t
        self._add_alert(Alert(ttype, sev, src, dst, desc))
