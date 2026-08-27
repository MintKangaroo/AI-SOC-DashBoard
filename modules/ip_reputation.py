"""
IP 평판 조회 (AbuseIPDB) 모듈

공격 출발지 IP가 전 세계에서 실제로 신고된 악성 IP인지 조회해
정탐/오탐 판정의 객관적 근거를 제공한다.

  - 실모드: ABUSEIPDB_API_KEY 설정 시 AbuseIPDB /api/v2/check 조회
            (무료 1,000 req/day — 캐시로 호출 최소화)
  - 데모모드: 키 없거나 조회 실패 시 결정론적 가짜 점수로 fallback
            (threat_intel 데모 악성 IP 목록은 높은 점수로 매핑)
  - 실전모드: 키 없음/API 실패 시 unavailable/0점 (가짜 점수 절대 사용 안 함)

반환 스키마(check):
  {ip, score(0~100), total_reports, country, isp, domain, usage_type,
   last_reported, source("abuseipdb"|"demo"|"internal"), cached, checked_at}

사설/CGNAT(Tailscale)/자기자신 IP는 조회하지 않는다(외부 API에 내부망 노출 방지).
"""
import time
import hashlib
import threading
from datetime import datetime
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)


def _stable_hash(s):
    """프로세스 재시작에도 동일한 해시 (builtin hash()는 시드 랜덤이라 부적합)."""
    return int(hashlib.md5(str(s).encode("utf-8")).hexdigest()[:8], 16)

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.",
                     "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

# 데모 fallback 에서 "확실한 악성"으로 취급할 IP (threat_intel DEMO_BAD_IPS 와 동일)
DEMO_BAD_IPS = {
    "45.155.205.233", "185.220.101.45", "193.32.162.157",
    "5.188.206.18", "91.240.118.172", "194.165.16.77",
    "103.91.91.9", "45.142.122.8", "185.142.236.34",
}
_DEMO_COUNTRIES = ["RU", "CN", "US", "NL", "DE", "BR", "IN", "VN", "KR", "FR"]
_DEMO_USAGE = ["Data Center/Web Hosting/Transit", "ISP", "Commercial", "Fixed Line ISP"]


class IPReputation:
    def __init__(self, socketio, config=None):
        self.socketio = socketio
        self.config = config or {}
        self.running = False
        self.demo_allowed = True
        self._lock = threading.Lock()

        self.api_key = (self.config.get("ABUSEIPDB_API_KEY") or "").strip()
        try:
            self.cache_ttl = float(self.config.get("ABUSEIPDB_CACHE_HOURS", 6)) * 3600
        except (TypeError, ValueError):
            self.cache_ttl = 6 * 3600
        try:
            # 이 점수 이상이면 "악성"으로 간주 (정탐 근거)
            self.min_score = int(self.config.get("ABUSEIPDB_MIN_SCORE", 75))
        except (TypeError, ValueError):
            self.min_score = 75

        self._cache = {}          # ip -> (result, expires_ts)
        self._own_ips = set()     # app.py 에서 주입(soar._own_ips 재사용 가능)
        self._recent = deque(maxlen=100)   # 최근 조회 결과(외부 IP만)
        self.stats = {
            "mode": "off",
            "total_checks": 0,
            "api_calls": 0,
            "cache_hits": 0,
            "malicious": 0,     # min_score 이상으로 판정된 수
            "errors": 0,
        }

    # ------------------------------------------------------------------ #
    #  라이프사이클 (온디맨드 조회라 스레드는 없지만 인터페이스 유지)
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        self.running = True
        self.demo_allowed = bool(demo)
        mode = "demo" if demo else "unavailable"
        if self.api_key and REQUESTS_OK and not demo:
            mode = "abuseipdb"
        elif self.api_key and REQUESTS_OK and demo:
            # 데모 모드라도 키가 있으면 실조회 허용 (실제 공격 IP 판정 목적)
            mode = "abuseipdb"
        with self._lock:
            self.stats["mode"] = mode
        if mode == "abuseipdb":
            _log.info("[IPRep] AbuseIPDB 실조회 활성 — 공격 IP 평판을 API로 확인합니다.")
        elif mode == "demo":
            _log.warning("[IPRep] ABUSEIPDB_API_KEY 없음 — 데모 평판 점수로 fallback.")
        else:
            _log.warning("[IPRep] AbuseIPDB 미설정 — 실전 모드에서는 평판 점수를 생성하지 않습니다.")

    def stop(self):
        self.running = False

    def set_own_ips(self, ips):
        self._own_ips = set(ips or [])

    # ------------------------------------------------------------------ #
    #  조회 API
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_internal(ip):
        if not ip:
            return True
        if ip.startswith(_PRIVATE_PREFIXES):
            return True
        try:                       # 100.64.0.0/10 (CGNAT/Tailscale)
            a, b = ip.split(".")[:2]
            if int(a) == 100 and 64 <= int(b) <= 127:
                return True
        except (ValueError, IndexError):
            return True
        return False

    def check(self, ip, force=False):
        """IP 평판 조회 (캐시 우선). 내부 IP 는 조회하지 않고 source=internal 반환."""
        if not ip or self._is_internal(ip) or ip in self._own_ips:
            return {"ip": ip, "score": 0, "source": "internal",
                    "total_reports": 0, "country": None, "cached": False,
                    "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        now = time.time()
        if not force:
            with self._lock:
                hit = self._cache.get(ip)
            if hit and hit[1] > now:
                with self._lock:
                    self.stats["cache_hits"] += 1
                result = dict(hit[0])
                result["cached"] = True
                return result

        result = self._lookup(ip)
        with self._lock:
            self._cache[ip] = (result, now + self.cache_ttl)
            self.stats["total_checks"] += 1
            if result.get("score", 0) >= self.min_score:
                self.stats["malicious"] += 1
            # 외부 IP 조회 이력(라이브 피드/패널용)
            self._recent.appendleft(result)
        # 실시간 스트림
        try:
            self.socketio.emit("ip_reputation", result)
        except Exception:
            pass
        return result

    def is_malicious(self, ip):
        """정탐 판정용 간편 헬퍼: (bool, score)"""
        r = self.check(ip)
        return r.get("score", 0) >= self.min_score, r.get("score", 0)

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "min_score": self.min_score,
                "cache_size": len(self._cache),
                "recent": list(self._recent)[:30],
            }

    # ------------------------------------------------------------------ #
    #  내부: 실제/데모 조회
    # ------------------------------------------------------------------ #

    def _lookup(self, ip):
        mode = self.stats.get("mode")
        if mode == "abuseipdb":
            r = self._lookup_abuseipdb(ip)
            if r is not None:
                return r
            # 실전 모드 API 실패는 가짜 점수로 대체하지 않는다.
            if not self.demo_allowed:
                return self._unavailable(ip)
        if mode == "demo":
            return self._lookup_demo(ip)
        return self._unavailable(ip)

    @staticmethod
    def _unavailable(ip):
        return {"ip": ip, "score": 0, "total_reports": 0, "country": None,
                "isp": None, "domain": None, "usage_type": None,
                "last_reported": None, "source": "unavailable", "cached": False,
                "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    def _lookup_abuseipdb(self, ip):
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=6,
            )
            with self._lock:
                self.stats["api_calls"] += 1
            if resp.status_code != 200:
                with self._lock:
                    self.stats["errors"] += 1
                return None
            d = (resp.json() or {}).get("data", {})
            return {
                "ip": ip,
                "score": int(d.get("abuseConfidenceScore", 0)),
                "total_reports": int(d.get("totalReports", 0)),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "usage_type": d.get("usageType"),
                "last_reported": d.get("lastReportedAt"),
                "source": "abuseipdb",
                "cached": False,
                "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        except Exception as e:
            with self._lock:
                self.stats["errors"] += 1
            _log.error(f"[IPRep] AbuseIPDB 조회 오류({ip}): {type(e).__name__}")
            return None

    def _lookup_demo(self, ip):
        """결정론적 가짜 점수 — 같은 IP는 항상 같은 결과(재현성: hashlib 사용)."""
        h = _stable_hash(ip)
        if ip in DEMO_BAD_IPS:
            score, reports = 100, 900 + (h % 400)
        else:
            # 대부분 저위험, 일부만 고위험으로 분포
            base = h % 100
            score = base if base > 60 else base % 25
            reports = (h % 300) if score >= 40 else (h % 15)
        cc = _DEMO_COUNTRIES[h % len(_DEMO_COUNTRIES)]
        return {
            "ip": ip,
            "score": int(score),
            "total_reports": int(reports),
            "country": cc,
            "isp": "Demo ISP",
            "domain": None,
            "usage_type": _DEMO_USAGE[h % len(_DEMO_USAGE)],
            "last_reported": None,
            "source": "demo",
            "cached": False,
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
