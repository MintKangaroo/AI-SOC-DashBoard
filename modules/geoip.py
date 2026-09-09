"""
GeoIP 모듈 - 공격 출발지 IP 위치 조회
ip-api.com (무료, 키 불필요) 또는 로컬 캐시 사용
"""
import threading
import time
import random
import requests
from collections import deque, OrderedDict

# 서울 좌표 (방어측 기준)
TARGET_LAT = 37.5665
TARGET_LNG = 126.9780
TARGET_CITY = "Seoul, South Korea"

# 로컬 LRU 캐시 (최대 500개 IP)
_CACHE = OrderedDict()
_CACHE_MAX = 500
_LOCK = threading.Lock()

# ip-api.com 무료 티어: 45 req/min → 호출 간 최소 1.5초 간격 유지
_MIN_API_INTERVAL = 1.5
_last_api_call = [0.0]
_RATE_LOCK = threading.Lock()


def lookup_ip(ip: str):
    """IP → 위도/경도 조회 (캐시 우선)"""
    if _is_private(ip):
        return None

    with _LOCK:
        if ip in _CACHE:
            _CACHE.move_to_end(ip)
            return _CACHE[ip]

    with _RATE_LOCK:
        wait = _MIN_API_INTERVAL - (time.time() - _last_api_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_api_call[0] = time.time()

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,lat,lon,isp,org,query"},
            timeout=3,
        )
        data = r.json()
        if data.get("status") != "success":
            return None

        result = {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "lat": data.get("lat", 0),
            "lng": data.get("lon", 0),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
        }

        with _LOCK:
            _CACHE[ip] = result
            if len(_CACHE) > _CACHE_MAX:
                _CACHE.popitem(last=False)

        return result

    except Exception:
        return None


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        first, second = int(parts[0]), int(parts[1])
        return (
            first == 10
            or first == 127
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
        )
    except ValueError:
        return True


# ------------------------------------------------------------------ #
#  데모용 가상 공격 좌표
# ------------------------------------------------------------------ #

DEMO_ATTACK_SOURCES = [
    {"country": "Russia",        "city": "Moscow",      "lat": 55.7558, "lng": 37.6176},
    {"country": "China",         "city": "Beijing",     "lat": 39.9042, "lng": 116.4074},
    {"country": "North Korea",   "city": "Pyongyang",   "lat": 39.0194, "lng": 125.7381},
    {"country": "Ukraine",       "city": "Kyiv",        "lat": 50.4501, "lng": 30.5234},
    {"country": "Brazil",        "city": "São Paulo",   "lat": -23.5505, "lng": -46.6333},
    {"country": "Romania",       "city": "Bucharest",   "lat": 44.4268, "lng": 26.1025},
    {"country": "USA",           "city": "Chicago",     "lat": 41.8781, "lng": -87.6298},
    {"country": "Germany",       "city": "Frankfurt",   "lat": 50.1109, "lng": 8.6821},
    {"country": "Netherlands",   "city": "Amsterdam",   "lat": 52.3676, "lng": 4.9041},
    {"country": "Iran",          "city": "Tehran",      "lat": 35.6892, "lng": 51.3890},
    {"country": "Vietnam",       "city": "Hanoi",       "lat": 21.0278, "lng": 105.8342},
    {"country": "India",         "city": "Mumbai",      "lat": 19.0760, "lng": 72.8777},
]


class AttackMapTracker:
    """지도 공격 추적기 — 실시간 공격 좌표 스트림 제공"""

    def __init__(self, socketio):
        self.socketio = socketio
        self.running = False
        self.recent_attacks = deque(maxlen=200)
        self._lookup_queue = deque(maxlen=100)
        self._lock = threading.Lock()

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        if demo:
            threading.Thread(target=self._demo_loop, daemon=True).start()
        else:
            threading.Thread(target=self._lookup_worker, daemon=True).start()

    def stop(self):
        self.running = False

    def add_attack_ip(self, src_ip, threat_type="UNKNOWN", severity="HIGH"):
        """실제 공격 IP 추가 — 비동기 GeoIP 조회"""
        self._lookup_queue.append({
            "ip": src_ip,
            "threat_type": threat_type,
            "severity": severity,
        })

    def get_recent_attacks(self, limit=50):
        with self._lock:
            return list(self.recent_attacks)[-limit:]

    # ------------------------------------------------------------------ #

    def _emit_attack(self, entry):
        entry = dict(entry)
        entry['timestamp_epoch'] = time.time()
        entry['destination_basis'] = 'display_anchor'  # Existing Seoul coordinates are not asset geolocation.
        entry['provenance'] = {'state': 'DEMO' if entry.get('demo') else 'UNAVAILABLE',
                               'reason': 'Generated map event' if entry.get('demo') else 'GeoIP lookup is real; original event provenance was not passed to the map.'}
        with self._lock:
            self.recent_attacks.append(entry)
        self.socketio.emit("map_attack", entry)

    def _demo_loop(self):
        time.sleep(1)
        while self.running:
            src = random.choice(DEMO_ATTACK_SOURCES).copy()
            src["lat"] += random.uniform(-2, 2)
            src["lng"] += random.uniform(-2, 2)

            threat_types = ["DDOS", "PORT_SCAN", "BRUTE_FORCE", "MALWARE_BEACON", "DATA_EXFIL"]
            severities   = ["CRITICAL", "CRITICAL", "HIGH", "HIGH", "MEDIUM"]
            idx = random.randint(0, len(threat_types) - 1)

            entry = {
                "demo": True,
                "src_lat":     src["lat"],
                "src_lng":     src["lng"],
                "src_country": src["country"],
                "src_city":    src["city"],
                "dst_lat":     TARGET_LAT,
                "dst_lng":     TARGET_LNG,
                "dst_city":    TARGET_CITY,
                "threat_type": threat_types[idx],
                "severity":    severities[idx],
                "ip":          f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "timestamp":   __import__("datetime").datetime.now().strftime("%H:%M:%S"),
            }
            self._emit_attack(entry)
            time.sleep(random.uniform(1.5, 4.0))

    def _lookup_worker(self):
        while self.running:
            if self._lookup_queue:
                item = self._lookup_queue.popleft()
                geo = lookup_ip(item["ip"])
                if geo:
                    entry = {
                        "src_lat":     geo["lat"],
                        "src_lng":     geo["lng"],
                        "src_country": geo["country"],
                        "src_city":    geo["city"],
                        "dst_lat":     TARGET_LAT,
                        "dst_lng":     TARGET_LNG,
                        "dst_city":    TARGET_CITY,
                        "threat_type": item["threat_type"],
                        "severity":    item["severity"],
                        "ip":          item["ip"],
                        "timestamp":   __import__("datetime").datetime.now().strftime("%H:%M:%S"),
                    }
                    self._emit_attack(entry)
            time.sleep(0.1)
