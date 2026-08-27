"""
패킷 분석 모듈 - PyShark / Scapy 기반
실제 캡처 불가 시 데모 데이터로 자동 전환
"""
import threading
import time
import random
import hashlib
from datetime import datetime
from collections import defaultdict, deque

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketAnalyzer:
    def __init__(self, socketio, config=None, threat_detector=None):
        self.socketio = socketio
        self.config = config

        def _cfg(key, default, cast=int, minimum=1):
            try:
                return max(minimum, cast((config or {}).get(key, default)))
            except (TypeError, ValueError):
                return default

        # 두 값은 config 에 선언돼 있었으나 아무 데서도 읽히지 않았다(AUDIT F-1).
        self.max_packets_display = _cfg("MAX_PACKETS_DISPLAY", 200)
        self.demo_interval = _cfg("DEMO_UPDATE_INTERVAL", 2.0, float, 0.1)
        self.threat_detector = threat_detector
        self.running = False
        self.thread = None

        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "arp_packets": 0,
            "other_packets": 0,
            "total_bytes": 0,
            "packets_per_sec": 0,
            "bytes_per_sec": 0,
        }

        self.recent_packets = deque(maxlen=self.max_packets_display)
        self.ip_counter = defaultdict(int)
        self.port_counter = defaultdict(int)
        self.protocol_counter = defaultdict(int)
        self._lock = threading.Lock()

        # 초당 트래픽 히스토리 (최대 60초)
        self.traffic_history = deque(maxlen=60)
        self._last_count = 0
        self._last_bytes = 0
        self._last_time = time.time()

    # ------------------------------------------------------------------ #
    #  공개 API
    # ------------------------------------------------------------------ #

    def start(self, interface=None, demo=True):
        if self.running:
            return
        self.running = True

        if not demo and (PYSHARK_AVAILABLE or SCAPY_AVAILABLE):
            target = self._capture_pyshark if PYSHARK_AVAILABLE else self._capture_scapy
            self.thread = threading.Thread(
                target=target, args=(interface,), daemon=True
            )
        else:
            self.thread = threading.Thread(target=self._demo_loop, daemon=True)

        self.thread.start()
        threading.Thread(target=self._emit_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def get_stats(self):
        with self._lock:
            stats = dict(self.stats)
            recent = list(self.recent_packets)
        # ML 피처용: 최근 패킷 윈도우 기준 고유 출발지/목적지 포트 수
        stats["unique_src_ips"] = len({p["src_ip"] for p in recent})
        stats["unique_dst_ports"] = len(
            {p["dst_port"] for p in recent if p.get("dst_port")}
        )
        return stats

    def get_recent_packets(self, limit=50):
        with self._lock:
            return list(self.recent_packets)[-limit:]

    def get_top_talkers(self, top=10):
        with self._lock:
            sorted_ips = sorted(self.ip_counter.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:top]

    def get_protocol_distribution(self):
        with self._lock:
            return dict(self.protocol_counter)

    def get_traffic_history(self):
        with self._lock:
            return list(self.traffic_history)

    # ------------------------------------------------------------------ #
    #  PyShark 캡처
    # ------------------------------------------------------------------ #

    def _capture_pyshark(self, interface):
        try:
            cap = pyshark.LiveCapture(
                interface=interface,
                bpf_filter="ip or arp",
            )
            for pkt in cap.sniff_continuously():
                if not self.running:
                    break
                self._process_pyshark_packet(pkt)
        except Exception as e:
            print(f"[PacketAnalyzer] PyShark error: {e} — fallback to demo")
            self._demo_loop()

    def _process_pyshark_packet(self, pkt):
        try:
            proto = pkt.highest_layer
            length = int(pkt.length) if hasattr(pkt, "length") else 0
            src_ip = pkt.ip.src if hasattr(pkt, "ip") else "unknown"
            dst_ip = pkt.ip.dst if hasattr(pkt, "ip") else "unknown"
            src_port = None
            dst_port = None

            if hasattr(pkt, "tcp"):
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                proto = "TCP"
            elif hasattr(pkt, "udp"):
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
                proto = "UDP"
            elif hasattr(pkt, "icmp"):
                proto = "ICMP"
            elif hasattr(pkt, "arp"):
                proto = "ARP"

            self._record_packet(src_ip, dst_ip, src_port, dst_port, proto, length)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Scapy 캡처
    # ------------------------------------------------------------------ #

    def _capture_scapy(self, interface):
        try:
            sniff(
                iface=interface,
                prn=self._process_scapy_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except Exception as e:
            print(f"[PacketAnalyzer] Scapy error: {e} — fallback to demo")
            self._demo_loop()

    def _process_scapy_packet(self, pkt):
        try:
            src_ip = dst_ip = "unknown"
            src_port = dst_port = None
            proto = "OTHER"
            length = len(pkt)

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            if TCP in pkt:
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"
            elif ARP in pkt:
                proto = "ARP"
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst

            self._record_packet(src_ip, dst_ip, src_port, dst_port, proto, length)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Demo 루프
    # ------------------------------------------------------------------ #

    DEMO_IPS = [
        "192.168.1.{}", "10.0.0.{}", "172.16.0.{}",
        "203.0.113.{}", "198.51.100.{}", "8.8.{}.{}",
    ]
    DEMO_PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "ARP", "OTHER"]
    DEMO_PORTS = [80, 443, 22, 53, 8080, 3389, 445, 135, 3306, 5432, 6379]

    def _rand_ip(self):
        template = random.choice(self.DEMO_IPS)
        return template.format(*[random.randint(1, 254) for _ in range(template.count("{}"))])

    def _demo_loop(self):
        # 현실적인 트래픽 시뮬레이션: 호스트 풀에서 주로 발생 + 가끔 새 IP
        # (완전 랜덤 IP는 고유 출발지 수를 왜곡해 ML 피처를 망가뜨림)
        src_pool = [self._rand_ip() for _ in range(15)]
        while self.running:
            batch = random.randint(5, 25)
            for _ in range(batch):
                proto = random.choice(self.DEMO_PROTOCOLS)
                src_ip = random.choice(src_pool) if random.random() < 0.9 else self._rand_ip()
                dst_ip = random.choice(src_pool) if random.random() < 0.5 else self._rand_ip()
                src_port = random.choice(self.DEMO_PORTS) if proto in ("TCP", "UDP") else None
                dst_port = random.choice(self.DEMO_PORTS) if proto in ("TCP", "UDP") else None
                length = random.randint(40, 1500)
                self._record_packet(src_ip, dst_ip, src_port, dst_port, proto, length)
            time.sleep(0.2)

    # ------------------------------------------------------------------ #
    #  공통 레코딩
    # ------------------------------------------------------------------ #

    def _record_packet(self, src_ip, dst_ip, src_port, dst_port, proto, length):
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        entry = {
            "time": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "length": length,
            "info": self._make_info(proto, src_port, dst_port, length),
        }

        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["total_bytes"] += length
            proto_key = f"{proto.lower()}_packets"
            if proto_key in self.stats:
                self.stats[proto_key] += 1
            else:
                self.stats["other_packets"] += 1
            self.protocol_counter[proto] += 1
            self.ip_counter[src_ip] += 1
            if dst_port:
                self.port_counter[dst_port] += 1
            self.recent_packets.append(entry)

        # 실시간 위협 탐지 연동 (락 밖에서 호출)
        if self.threat_detector:
            try:
                self.threat_detector.analyze_packet(
                    src_ip, dst_ip, dst_port, proto, length
                )
            except Exception:
                pass

    def _make_info(self, proto, src_port, dst_port, length):
        if proto == "TCP":
            return f"{src_port} → {dst_port} [{length}B]"
        if proto == "UDP":
            return f"UDP {src_port} → {dst_port}"
        if proto == "ICMP":
            return "ICMP Echo"
        if proto == "ARP":
            return "ARP Request/Reply"
        return f"{proto} {length}B"

    # ------------------------------------------------------------------ #
    #  SocketIO emit 루프
    # ------------------------------------------------------------------ #

    def _emit_loop(self):
        while self.running:
            now = time.time()
            elapsed = now - self._last_time

            with self._lock:
                # 카운터 무한 증가 방지: IP/포트가 너무 많아지면 상위 항목만 유지
                if len(self.ip_counter) > 5000:
                    top = sorted(self.ip_counter.items(),
                                 key=lambda x: x[1], reverse=True)[:1000]
                    self.ip_counter = defaultdict(int, top)
                if len(self.port_counter) > 20000:
                    top = sorted(self.port_counter.items(),
                                 key=lambda x: x[1], reverse=True)[:5000]
                    self.port_counter = defaultdict(int, top)
                cur_packets = self.stats["total_packets"]
                cur_bytes = self.stats["total_bytes"]
                pps = int((cur_packets - self._last_count) / max(elapsed, 0.001))
                bps = int((cur_bytes - self._last_bytes) / max(elapsed, 0.001))
                self.stats["packets_per_sec"] = pps
                self.stats["bytes_per_sec"] = bps
                self._last_count = cur_packets
                self._last_bytes = cur_bytes
                self._last_time = now
                self.traffic_history.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "pps": pps,
                    "bps": bps,
                })
                payload = {
                    "stats": dict(self.stats),
                    "traffic_history": list(self.traffic_history)[-30:],
                    "top_talkers": sorted(self.ip_counter.items(), key=lambda x: x[1], reverse=True)[:10],
                    "protocol_dist": dict(self.protocol_counter),
                    "recent_packets": list(self.recent_packets)[-20:],
                }

            self.socketio.emit("packet_update", payload)
            time.sleep(self.demo_interval)
