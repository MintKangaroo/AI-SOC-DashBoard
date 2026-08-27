"""
위협 인텔리전스 (Threat Intelligence) 모듈
공개 IoC 피드에서 악성 IP / URL 을 주기적으로 수집하고,
네트워크 통신이 해당 목록과 일치하면 경보를 발생시킨다.

사용 피드 (공개):
- 악성 IP:
  * https://feodotracker.abuse.ch/downloads/ipblocklist.txt  (Feodo/Emotet/TrickBot C2)
  * https://reputation.alienvault.com/reputation.generic     (AlienVault OTX)
  * https://www.spamhaus.org/drop/drop.txt                   (Spamhaus DROP)
- 악성 URL/도메인:
  * https://urlhaus.abuse.ch/downloads/text/                 (URLhaus - 활성 악성 URL)
  * https://openphish.com/feed.txt                           (OpenPhish)

네트워크 제한/차단 등으로 피드를 가져오지 못하면 내장 데모 목록으로 fallback.
"""
import threading
import time
import re
import random
from datetime import datetime
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ───────── 공개 피드 엔드포인트 ─────────
IP_FEEDS = [
    ("Feodo Tracker",  "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",  "ip"),
    ("Spamhaus DROP",  "https://www.spamhaus.org/drop/drop.txt",                    "ip_cidr"),
]
URL_FEEDS = [
    ("URLhaus",   "https://urlhaus.abuse.ch/downloads/text/"),
    ("OpenPhish", "https://openphish.com/feed.txt"),
]

# 피드 실패 시 사용할 내장 샘플(학습용 데모 데이터)
DEMO_BAD_IPS = [
    "45.155.205.233", "185.220.101.45", "193.32.162.157",
    "5.188.206.18",   "91.240.118.172", "194.165.16.77",
    "103.91.91.9",    "45.142.122.8",   "185.142.236.34",
]
DEMO_BAD_URLS = [
    "http://evil-c2.xyz/gate.php",
    "http://malware-beacon.ru/update",
    "http://phish-login-microsoft.click/auth",
    "http://cryptominer.tech/pool",
    "http://tracker.badguy.cn/cmd",
]


# ───────── 유틸 ─────────
_IPv4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

def _parse_ip_list(text):
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        # "1.2.3.4/24 ; comment" 같은 라인 처리
        token = line.split()[0].split(";")[0].strip()
        if "/" in token:        # CIDR → 대표 IP(네트워크 주소)만 수집 (일치 검사는 단순)
            token = token.split("/")[0]
        if _IPv4_RE.match(token) and all(0 <= int(o) <= 255 for o in token.split(".")):
            ips.add(token)
    return ips


def _parse_url_list(text):
    urls = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            urls.add(line.split()[0])
    return urls


# ───────── 위협 인텔 트래커 ─────────
class ThreatIntel:
    def __init__(self, socketio, packet_analyzer=None, mitre_tracker=None):
        self.socketio = socketio
        self.packet_analyzer = packet_analyzer
        self.mitre = mitre_tracker
        self.soar = None   # app.py 에서 주입
        self.running = False

        self.bad_ips = set()
        self.bad_urls = set()
        self.feed_sources = []       # [{name, type, count, updated, status}]
        self.matches = deque(maxlen=200)  # 최근 매칭 이벤트
        self.stats = {
            "bad_ip_count": 0,
            "bad_url_count": 0,
            "total_matches": 0,
            "ip_matches": 0,
            "url_matches": 0,
            "last_refresh": None,
        }
        self._lock = threading.Lock()

    # ─────────────────────────── API ─────────────────────────── #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._refresh_loop, daemon=True).start()
        threading.Thread(target=self._match_loop, args=(demo,), daemon=True).start()

    def stop(self):
        self.running = False

    def get_status(self):
        with self._lock:
            return {
                "stats":   dict(self.stats),
                "sources": list(self.feed_sources),
                "matches": list(reversed(list(self.matches)))[:30],
                "sample_bad_ips":  list(self.bad_ips)[:20],
                "sample_bad_urls": list(self.bad_urls)[:20],
            }

    def check_ip(self, ip):
        """외부에서 호출 가능: IP가 악성인지 확인."""
        with self._lock:
            return ip in self.bad_ips

    def check_url(self, url):
        with self._lock:
            return any(bad in url for bad in self.bad_urls)

    # ──────────────────── 피드 갱신 루프 ──────────────────── #

    def _refresh_loop(self):
        # 시작하자마자 한 번, 그 뒤 30분마다
        while self.running:
            self._refresh_feeds()
            for _ in range(30 * 60):
                if not self.running:
                    return
                time.sleep(1)

    def _refresh_feeds(self):
        sources = []
        new_ips, new_urls = set(), set()

        if not REQUESTS_OK:
            _log.warning("[ThreatIntel] requests 미설치 — 데모 데이터 사용")
            new_ips.update(DEMO_BAD_IPS)
            new_urls.update(DEMO_BAD_URLS)
            sources.append({
                "name": "Demo (내장)", "type": "ip+url",
                "count": len(DEMO_BAD_IPS) + len(DEMO_BAD_URLS),
                "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "ok",
            })
        else:
            for name, url, kind in IP_FEEDS:
                try:
                    r = requests.get(url, timeout=8,
                                     headers={"User-Agent": "SOC-Dashboard/1.0"})
                    if r.status_code == 200:
                        ips = _parse_ip_list(r.text)
                        new_ips.update(ips)
                        sources.append({
                            "name": name, "type": kind, "count": len(ips),
                            "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "status": "ok",
                        })
                    else:
                        sources.append({"name": name, "type": kind, "count": 0,
                                        "updated": None, "status": f"HTTP {r.status_code}"})
                except Exception as e:
                    sources.append({"name": name, "type": kind, "count": 0,
                                    "updated": None, "status": f"오류: {type(e).__name__}"})

            for name, url in URL_FEEDS:
                try:
                    r = requests.get(url, timeout=8,
                                     headers={"User-Agent": "SOC-Dashboard/1.0"})
                    if r.status_code == 200:
                        urls = _parse_url_list(r.text)
                        new_urls.update(urls)
                        sources.append({
                            "name": name, "type": "url", "count": len(urls),
                            "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "status": "ok",
                        })
                    else:
                        sources.append({"name": name, "type": "url", "count": 0,
                                        "updated": None, "status": f"HTTP {r.status_code}"})
                except Exception as e:
                    sources.append({"name": name, "type": "url", "count": 0,
                                    "updated": None, "status": f"오류: {type(e).__name__}"})

            # 모든 피드가 비었으면 데모로 보강
            if not new_ips and not new_urls:
                new_ips.update(DEMO_BAD_IPS)
                new_urls.update(DEMO_BAD_URLS)
                sources.append({
                    "name": "Demo fallback", "type": "ip+url",
                    "count": len(DEMO_BAD_IPS) + len(DEMO_BAD_URLS),
                    "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "ok (fallback)",
                })

        with self._lock:
            self.bad_ips = new_ips
            self.bad_urls = new_urls
            self.feed_sources = sources
            self.stats["bad_ip_count"]  = len(new_ips)
            self.stats["bad_url_count"] = len(new_urls)
            self.stats["last_refresh"]  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        _log.info(f"[ThreatIntel] 피드 갱신: 악성 IP {len(new_ips):,}개 / URL {len(new_urls):,}개")
        self.socketio.emit("ti_feed_update", self.get_status())

    # ─────────────── 실시간 매칭 루프 ─────────────── #

    def _match_loop(self, demo):
        # 피드 로딩 대기
        time.sleep(3)
        while self.running:
            # HIGH 매칭이 과도하게 쌓이지 않도록 주기 완화
            time.sleep(random.uniform(25.0, 70.0))
            try:
                if demo or not self.packet_analyzer:
                    self._demo_match()
                else:
                    self._check_real_traffic()
            except Exception as e:
                _log.error(f"[ThreatIntel] 매칭 오류: {e}")

    def _demo_match(self):
        """데모 모드: 가끔 악성 IP/URL 통신 이벤트를 생성."""
        with self._lock:
            ips  = list(self.bad_ips)
            urls = list(self.bad_urls)
        if not ips and not urls:
            return

        # 30% IP / 70% URL 로 분배
        if ips and (not urls or random.random() < 0.3):
            ip = random.choice(ips)
            self._emit_match({
                "kind": "ip",
                "indicator": ip,
                "direction": random.choice(["outbound", "inbound"]),
                "local_ip": f"192.168.1.{random.randint(10, 250)}",
                "port": random.choice([80, 443, 4444, 8080, 53, 8443]),
                "description": f"악성 C2/봇넷 IP와 통신 감지 ({ip})",
            })
        elif urls:
            url = random.choice(urls)
            self._emit_match({
                "kind": "url",
                "indicator": url,
                "direction": "outbound",
                "local_ip": f"192.168.1.{random.randint(10, 250)}",
                "port": 80 if url.startswith("http://") else 443,
                "description": f"악성 URL 접근 시도 ({url[:80]})",
            })

    def _check_real_traffic(self):
        """실트래픽 모드: PacketAnalyzer의 최근 패킷에서 매칭 검사."""
        if not self.packet_analyzer:
            return
        pkts = self.packet_analyzer.get_recent_packets(50)
        with self._lock:
            ips = set(self.bad_ips)
        for p in pkts:
            for key in ("src_ip", "dst_ip"):
                ip = p.get(key)
                if ip and ip in ips:
                    self._emit_match({
                        "kind": "ip",
                        "indicator": ip,
                        "direction": "outbound" if key == "dst_ip" else "inbound",
                        "local_ip": p.get("src_ip") if key == "dst_ip" else p.get("dst_ip"),
                        "port": p.get("dst_port") or p.get("src_port"),
                        "description": f"악성 IP 통신 감지 ({ip})",
                    })

    def _emit_match(self, m):
        m["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        m["severity"]  = "HIGH"
        with self._lock:
            self.matches.append(m)
            self.stats["total_matches"] += 1
            if m["kind"] == "ip":  self.stats["ip_matches"]  += 1
            if m["kind"] == "url": self.stats["url_matches"] += 1

        self.socketio.emit("ti_match", m)
        if self.soar:
            try:
                self.soar.handle_ti_match(m)
            except Exception:
                pass
        # MITRE: T1071 (Application Layer Protocol — C2 통신) 매핑
        if self.mitre:
            try:
                self.mitre.map_threat(
                    "MALWARE_BEACON",
                    src_ip=m.get("local_ip"),
                    dst_ip=m.get("indicator") if m["kind"] == "ip" else None,
                    description=m["description"],
                )
            except Exception:
                pass
