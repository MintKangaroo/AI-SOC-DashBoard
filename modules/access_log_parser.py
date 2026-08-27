"""
SIEM 접근 로그 수집 모듈
외부 프로젝트(자동매매 KR/USA 등)의 웹서버 access log를 tail 방식으로 수집·파싱하고,
의심 요청(스캔/프로브)을 분류해 SocketIO로 스트리밍한다.

지원 형식: werkzeug / http.server 공통 로그
  1.2.3.4 - - [02/Jun/2026 09:04:27] "GET / HTTP/1.1" 200 -
  1.2.3.4 - - [02/Jun/2026 09:04:14] code 400, message Bad request version (...)

로그 파일이 없으면 데모 이벤트 생성으로 fallback.

## 첫 적재(backfill) 처리

이전 구현은 시작 시 로그 전체를 읽으면서 `emit=False` 로 돌았고,
`_record_event` 가 그 경우 통계만 올리고 조기 반환했다. 결과적으로
**과거 로그의 탐지 결과가 전부 폐기됐다** (실측: 실제 HIGH 정찰 31건 유실,
docs/CASE_STUDIES.md 사례 1).

UI 를 폭주시키지 않으려는 의도는 옳았으나 구현이 틀렸다 —
표시를 억제하는 것과 탐지를 버리는 것은 다르다. 지금은 모드를 나눈다.

| | backfill (첫 적재) | live (이후) |
|---|---|---|
| 이벤트 목록·통계 | ✓ | ✓ |
| MITRE 매핑 | ✓ (과거 공격면 파악) | ✓ |
| 실시간 스트림 emit | ✗ (요약 1건만) | ✓ |
| 공격 지도 | ✗ (실시간 지도라 과거 표시는 오독) | ✓ |
| SOAR | ✗ (지난 이벤트로 자동대응 금지) | ✓ |
| 알림(Alert) 승격 | ✗ | ✓ |

offset 을 파일에 영속화해 재시작마다 전체를 재처리하지 않는다.
영속화가 없으면 backfill 처리를 켜는 순간 재시작마다 중복이 쏟아진다.
"""
import json
import os
import re
import time
import random
import threading
from datetime import datetime
from collections import deque, Counter

# 기본 수집 대상 (자동매매 프로젝트 대시보드 서버 로그)
DEFAULT_SOURCES = [
    {"name": "자동매매 KR",
     "path": "/home/mintkangaroo/Project/Invest_KOREA_Stock_Project/ls_kr_rl_trader/storage/logs/server.log"},
    {"name": "자동매매 USA",
     "path": "/home/mintkangaroo/Project/Invest_USA_Stock_Project/ls_us_rl_trader/logs/run.log"},
]

# werkzeug/http.server 접근 라인: IP - - [date] 나머지
_ACCESS_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}) - - \[([^\]]+)\] (.*)$')
# "REQUEST" STATUS -
_REQ_RE = re.compile(r'^"(.*)" (\d{3}) -?\s*$')

_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.",
                     "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


# 수집 상태(offset) 영속화 경로 — 없으면 재시작마다 로그 전체를 재처리한다
DEFAULT_STATE_PATH = "data/siem_offsets.json"

# 카테고리 → 알림 위협유형. syslog_receiver._CATEGORY_THREAT 와 같은 방식이다.
#
# 주의: 여기서 고르는 위협유형은 SOAR 자동차단 플레이북과 직결된다.
# PB-BRUTE-BLOCK 은 BRUTE_FORCE, PB-HONEYPOT-BLOCK 은 HONEYPOT 에만 반응하므로
# 아래 매핑은 **어떤 자동차단 경로도 열지 않는다**. 스캐너 프로브 한 건으로
# 운영 서버 앞단 방화벽이 움직이면 안 되기 때문이다.
# (tests/test_siem_backfill.py 가 이 불변식을 검증한다)
_CATEGORY_THREAT = {
    "TLS 프로브 (HTTPS 스캔)": "PORT_SCAN",
    "바이너리 프로브 (프로토콜 스캔)": "PORT_SCAN",
    "HTTP/2 프로브": "PORT_SCAN",
    "환경파일 탈취 시도": "WEB_ATTACK",
    "WordPress 스캔": "WEB_ATTACK",
    "관리자 페이지 스캔": "WEB_ATTACK",
    "phpMyAdmin 스캔": "WEB_ATTACK",
    "Git 저장소 노출 스캔": "WEB_ATTACK",
    "CGI 취약점 스캔": "WEB_ATTACK",
    "IoT 취약점 스캔": "WEB_ATTACK",
    "웹쉘 접근 시도": "WEB_ATTACK",
}

# 알림으로 승격하지 않는 위협유형 — 자동차단 플레이북이 반응하는 유형은 넣지 않는다
_NEVER_PROMOTE_AS = ("BRUTE_FORCE", "HONEYPOT", "DATA_EXFIL", "DNS_TUNNELING")


def classify_request(request, status):
    """요청 문자열/상태코드 → (suspicious, severity, category)"""
    if request.startswith("\\x16\\x03"):
        return True, "HIGH", "TLS 프로브 (HTTPS 스캔)"
    if "\\x" in request:
        return True, "HIGH", "바이너리 프로브 (프로토콜 스캔)"
    if request.startswith("PRI * HTTP/2"):
        return True, "HIGH", "HTTP/2 프로브"
    low = request.lower()
    for kw, cat in (("/.env", "환경파일 탈취 시도"),
                    ("/wp-", "WordPress 스캔"),
                    ("/admin", "관리자 페이지 스캔"),
                    ("/phpmyadmin", "phpMyAdmin 스캔"),
                    ("/.git", "Git 저장소 노출 스캔"),
                    ("/cgi-bin", "CGI 취약점 스캔"),
                    ("/boaform", "IoT 취약점 스캔"),
                    ("/shell", "웹쉘 접근 시도")):
        if kw in low:
            return True, "CRITICAL", cat
    # 일반 4xx/5xx 는 오탐이 많아 '의심'으로 올리지 않음 (프로브/스캔 패턴만 의심)
    if status >= 400:
        return False, "LOW", f"클라이언트 오류 (HTTP {status})"
    return False, "INFO", "정상 요청"


class AccessLogCollector:
    """외부 access log 수집기 — start()/stop()/get_events() 인터페이스"""

    POLL_INTERVAL = 5.0

    def __init__(self, socketio, sources=None, mitre_tracker=None, attack_map=None,
                 threat_detector=None, state_path=DEFAULT_STATE_PATH,
                 promote_alerts=True):
        self.socketio = socketio
        self.mitre = mitre_tracker
        self.attack_map = attack_map
        self.soar = None              # wiring.py 에서 주입
        self.threat_detector = threat_detector  # HIGH/CRITICAL 프로브 → 알림 승격
        self.promote_alerts = promote_alerts
        self.state_path = state_path
        self.running = False
        self._lock = threading.Lock()

        self.events = deque(maxlen=1000)
        self.ip_counter = Counter()
        self.stats = {
            "total_events": 0,
            "suspicious_events": 0,
            "backfilled_suspicious": 0,
            "unique_ips": 0,
            "sources_ok": 0,
            "last_event": None,
        }

        saved = self._load_state()
        self.sources = []
        for src in (sources or DEFAULT_SOURCES):
            path = src["path"]
            prev = saved.get(path) or {}
            # 저장된 offset 이 현재 파일보다 크면 로테이션된 것 → 0 부터
            offset = int(prev.get("offset", 0))
            try:
                if offset > os.path.getsize(path):
                    offset = 0
            except OSError:
                offset = 0
            self.sources.append({
                "name": src["name"],
                "path": path,
                "exists": os.path.exists(path),
                "offset": offset,
                "backfilled": bool(prev.get("backfilled")),
                "events": 0,
                "suspicious": 0,
                "last_read": None,
            })

    # ------------------------------------------------------------------ #
    #  수집 상태 영속화 — 재시작마다 전체를 재처리하지 않기 위함
    # ------------------------------------------------------------------ #

    def _load_state(self):
        if not self.state_path or not os.path.exists(self.state_path):
            return {}
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError) as e:
            print(f"[SIEM] 수집 상태 로드 실패({e}) — 처음부터 읽음")
            return {}

    def _save_state(self):
        """offset 저장 실패가 수집을 멈추면 안 된다 — 로그만 남긴다."""
        if not self.state_path:
            return
        try:
            directory = os.path.dirname(self.state_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with self._lock:
                data = {s["path"]: {"offset": s["offset"],
                                    "backfilled": s["backfilled"],
                                    "name": s["name"]}
                        for s in self.sources}
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.state_path)
        except OSError as e:
            print(f"[SIEM] 수집 상태 저장 실패({e})")

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        if any(s["exists"] for s in self.sources):
            threading.Thread(target=self._collect_loop, daemon=True).start()
        elif demo:
            print("[SIEM] 접근 로그 파일 없음 — 데모 이벤트 생성")
            threading.Thread(target=self._demo_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def get_events(self, limit=100, source=None, suspicious_only=False):
        with self._lock:
            result = list(self.events)
        if source:
            result = [e for e in result if e["source"] == source]
        if suspicious_only:
            result = [e for e in result if e["suspicious"]]
        return list(reversed(result))[:limit]

    def get_stats(self):
        with self._lock:
            stats = dict(self.stats)
            stats["unique_ips"] = len(self.ip_counter)
            stats["top_ips"] = self.ip_counter.most_common(10)
        return stats

    def get_status(self):
        with self._lock:
            sources = [{k: s[k] for k in
                        ("name", "path", "exists", "events", "suspicious", "last_read")}
                       for s in self.sources]
        return {
            "stats": self.get_stats(),
            "sources": sources,
            "events": self.get_events(100),
        }

    # ------------------------------------------------------------------ #

    def _collect_loop(self):
        first_pass = True
        while self.running:
            backfill_summary = []
            for src in self.sources:
                # 이 소스를 아직 backfill 하지 않았다면 이번 읽기가 backfill 이다.
                # 영속 offset 덕에 재시작해도 두 번 돌지 않는다.
                mode = "backfill" if (first_pass and not src["backfilled"]) else "live"
                before = src["suspicious"]
                try:
                    self._read_source(src, mode=mode)
                except Exception as e:
                    print(f"[SIEM] {src['name']} 읽기 오류: {e}")
                if mode == "backfill":
                    src["backfilled"] = True
                    found = src["suspicious"] - before
                    if found:
                        backfill_summary.append((src["name"], found))
            self._save_state()

            if first_pass:
                first_pass = False
                self._emit_backfill_summary(backfill_summary)
                # 초기 적재 완료 상태를 한 번 브로드캐스트
                self.socketio.emit("siem_status", self.get_status())
            for _ in range(int(self.POLL_INTERVAL * 10)):
                if not self.running:
                    return
                time.sleep(0.1)

    def _emit_backfill_summary(self, summary):
        """과거 로그에서 찾은 탐지를 요약 1건으로 알린다.

        개별 이벤트를 스트리밍하면 UI 가 폭주하므로 요약만 보낸다.
        조용히 버리지 않는다는 점이 이전 구현과의 차이다.
        """
        total = sum(n for _, n in summary)
        if not total:
            return
        detail = " · ".join(f"{name} {n}건" for name, n in summary)
        print(f"[SIEM] 과거 로그 적재 완료 — 의심 이벤트 {total}건 ({detail})")
        try:
            self.socketio.emit("siem_backfill", {
                "total": total,
                "sources": [{"name": n, "suspicious": c} for n, c in summary],
                "detail": detail,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        except Exception:
            pass

    def _read_source(self, src, mode="live"):
        if not os.path.exists(src["path"]):
            src["exists"] = False
            return
        src["exists"] = True
        size = os.path.getsize(src["path"])
        if size < src["offset"]:            # 로그 로테이션 감지
            src["offset"] = 0
        if size == src["offset"]:
            return

        with open(src["path"], "r", encoding="utf-8", errors="replace") as f:
            f.seek(src["offset"])
            chunk = f.read()
            src["offset"] = f.tell()
        src["last_read"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for line in chunk.splitlines():
            event = self._parse_line(line, src["name"])
            if event:
                src["events"] += 1
                if event["suspicious"]:
                    src["suspicious"] += 1
                self._record_event(event, mode=mode)

    def _parse_line(self, line, source_name):
        m = _ACCESS_RE.match(line.strip())
        if not m:
            return None
        ip, ts, rest = m.groups()
        # "code NNN, message ..." 라인은 뒤따르는 요청 라인과 중복 — 건너뜀
        if rest.startswith("code "):
            return None
        rm = _REQ_RE.match(rest)
        if not rm:
            return None
        request, status = rm.group(1), int(rm.group(2))
        suspicious, severity, category = classify_request(request, status)
        return {
            "source": source_name,
            "ip": ip,
            "timestamp": ts,
            "request": request[:200],
            "status": status,
            "suspicious": suspicious,
            "severity": severity,
            "category": category,
        }

    def _record_event(self, event, mode="live"):
        """이벤트 1건을 기록한다.

        mode="backfill" 은 과거 로그를 처음 읽는 경우다. 탐지 결과를 버리지 않되
        (MITRE 는 반영) 실시간 성격의 부수효과는 건너뛴다 — 지난 이벤트로
        공격 지도를 칠하거나 SOAR 자동대응을 돌리면 안 되기 때문이다.
        """
        backfill = (mode == "backfill")
        with self._lock:
            self.events.append(event)
            self.ip_counter[event["ip"]] += 1
            self.stats["total_events"] += 1
            if event["suspicious"]:
                self.stats["suspicious_events"] += 1
                if backfill:
                    self.stats["backfilled_suspicious"] += 1
            self.stats["last_event"] = event["timestamp"]
            self.stats["sources_ok"] = sum(1 for s in self.sources if s["exists"])

        # HIGH/CRITICAL 외부 프로브만 후속 처리 (MEDIUM 이하 노이즈 차단)
        actionable = (event["suspicious"]
                      and event["severity"] in ("HIGH", "CRITICAL")
                      and self._is_external(event["ip"]))

        # MITRE 는 backfill 에서도 반영한다 — 과거 공격면을 알아야 하기 때문.
        if actionable and self.mitre:
            try:
                self.mitre.map_threat(
                    "ANOMALY", src_ip=event["ip"],
                    description=f"[SIEM/{event['source']}] {event['category']}")
            except Exception:
                pass

        if backfill:
            return      # 스트림·지도·SOAR·알림승격은 실시간에만

        self.socketio.emit("siem_event", event)
        if not actionable:
            return

        if self.attack_map:
            try:
                self.attack_map.add_attack_ip(event["ip"], "PORT_SCAN",
                                              event["severity"])
            except Exception:
                pass
        self._promote_to_alert(event)
        if self.soar:
            try:
                self.soar.handle_siem_event(event)
            except Exception:
                pass

    def _promote_to_alert(self, event):
        """HIGH/CRITICAL 외부 프로브를 알림으로 승격한다.

        이전에는 SIEM 파일 tail 이벤트가 알림이 되지 않아 alerts.db 에 남지
        않았고, 검색·확정판정·인시던트 워크플로 어디에도 들어가지 못했다.
        (syslog_receiver 는 같은 일을 이미 하고 있다 — 그 선례를 따른다.)

        위협유형은 자동차단 플레이북이 반응하지 않는 것만 고른다. 스캐너 프로브
        한 건으로 운영 서버 방화벽이 움직이면 안 된다.
        """
        if not (self.promote_alerts and self.threat_detector):
            return
        threat_type = _CATEGORY_THREAT.get(event["category"], "ANOMALY")
        if threat_type in _NEVER_PROMOTE_AS:      # 방어적 — 매핑 실수 차단
            threat_type = "ANOMALY"
        try:
            self.threat_detector.report_alert(
                threat_type, event["severity"], event["ip"], "",
                f"[SIEM/{event['source']}] {event['category']} — {event['request'][:120]}",
                details={
                    "siem_source": event["source"],
                    "category": event["category"],
                    "request": event["request"][:200],
                    "status": event["status"],
                    "log_timestamp": event["timestamp"],
                },
            )
        except Exception as e:
            print(f"[SIEM] 알림 승격 실패({e}) — 이벤트는 기록됨")

    @staticmethod
    def _is_external(ip):
        return bool(ip) and not ip.startswith(_PRIVATE_PREFIXES)

    # ------------------------------------------------------------------ #
    #  데모 fallback
    # ------------------------------------------------------------------ #

    _DEMO_REQUESTS = [
        ('GET / HTTP/1.1', 200), ('GET /api/status HTTP/1.1', 200),
        ('GET /.env HTTP/1.1', 404), ('PRI * HTTP/2.0', 505),
        ('GET /wp-login.php HTTP/1.1', 404),
        ('\\x16\\x03\\x01\\x00\\xee', 400),
        ('GET /admin HTTP/1.1', 403), ('POST /api/login HTTP/1.1', 401),
    ]

    def _demo_loop(self):
        names = [s["name"] for s in self.sources] or ["데모 소스"]
        time.sleep(2)
        while self.running:
            req, status = random.choice(self._DEMO_REQUESTS)
            suspicious, severity, category = classify_request(req, status)
            self._record_event({
                "source": random.choice(names),
                "ip": f"{random.randint(1,223)}.{random.randint(0,254)}."
                      f"{random.randint(0,254)}.{random.randint(1,254)}",
                "timestamp": datetime.now().strftime("%d/%b/%Y %H:%M:%S"),
                "request": req,
                "status": status,
                "suspicious": suspicious,
                "severity": severity,
                "category": category,
            })
            time.sleep(random.uniform(3.0, 8.0))
