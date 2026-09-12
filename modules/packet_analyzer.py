"""
패킷 분석 모듈 - PyShark / Scapy 기반
실제 캡처 불가 시 데모 데이터로 자동 전환
"""
import asyncio
import os
import subprocess
import threading
import time
import random
from datetime import datetime
from collections import defaultdict, deque

from modules.logging_setup import get_logger

try:                                    # 캡처 프로세스의 메모리를 재는 데만 쓴다
    import psutil
except ImportError:                     # 없으면 시간 기준 재활용만 동작한다
    psutil = None

_log = get_logger(__name__)


try:
    import pyshark
    import pyshark.capture.capture
    from pyshark.tshark.tshark import get_process_path
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class _FdSafeLiveCapture(pyshark.LiveCapture if PYSHARK_AVAILABLE else object):
    """pyshark 의 파일 서술자 누수를 막은 LiveCapture.

    pyshark 는 dumpcap → tshark 를 잇느라 `os.pipe()` 를 만들고 두 끝을 자식에게
    넘긴 뒤, **부모 쪽 사본을 닫지 않는다**(live_capture.py `_get_tshark_process`).
    캡처를 한 번만 띄우던 시절에는 안 보였지만, 주기적으로 재활용하면 캡처마다
    2개씩 샌다 — 30분 주기면 하루 96개, 기본 상한 1,024개를 열흘이면 넘는다
    (실측 2026-09-12: 사이클마다 정확히 2개).

    자식은 spawn 할 때 자기 사본을 이미 가지므로 부모 쪽은 닫아도 된다. 오히려
    닫아야 dumpcap 이 죽었을 때 tshark 가 EOF 를 본다.
    """

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        read, write = os.pipe()
        dumpcap_params = [get_process_path(process_name="dumpcap",
                                           tshark_path=self.tshark_path)]
        dumpcap_params += self._get_dumpcap_parameters()
        dumpcap_process = await asyncio.create_subprocess_exec(
            *dumpcap_params, stdout=write, stderr=subprocess.PIPE)
        self._create_stderr_handling_task(dumpcap_process.stderr)
        self._created_new_process(dumpcap_params, dumpcap_process, process_name="Dumpcap")
        tshark = await pyshark.capture.capture.Capture._get_tshark_process(
            self, packet_count=packet_count, stdin=read)
        # 여기가 원본과 다른 전부 — 부모 쪽 사본을 닫는다.
        for fd in (read, write):
            try:
                os.close(fd)
            except OSError:
                pass
        return tshark


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
        # 캡처 재활용 — 아래 _capture_pyshark 주석 참조
        self.capture_recycle_seconds = _cfg("CAPTURE_RECYCLE_MINUTES", 30) * 60
        self.capture_max_rss_mb = _cfg("CAPTURE_MAX_RSS_MB", 700)
        self.capture_cycles = 0
        self.threat_detector = threat_detector
        self.running = False
        self.thread = None
        # 실제로 무슨 경로로 트래픽이 들어왔는가 — "real"(캡처) | "demo"(합성).
        # 설정(DEMO_MODE)이 아니라 **실행 결과**다. 캡처 백엔드가 없거나 캡처가
        # 실패해 데모로 폴백하면 여기가 "demo" 로 바뀐다. ML 피처의 origin 이
        # 이 값을 따라야 합성 트래픽이 실트래픽으로 둔갑하지 않는다.
        self.source_mode = "demo"

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
            # 인터페이스 미지정이면 기본 라우트 장치를 고른다. PyShark 에 None 을
            # 넘기면 "모든 인터페이스" 인데, WSL 처럼 도커 브리지가 20개 넘게 있는
            # 호스트에서 그 목록이 '-'(표준입력) 하나로 무너져 dumpcap 이 -i - 로
            # 떠서 패킷 0건이었다(실측 2026-09-08). 실모드인데 0 pps 면 실패다.
            if not interface:
                interface = self.default_interface()
                _log.info(f"[PacketAnalyzer] 캡처 인터페이스 자동 선택: {interface or '(전체)'}")
            self.interface = interface
            target = self._capture_pyshark if PYSHARK_AVAILABLE else self._capture_scapy
            self.source_mode = "real"
            self.thread = threading.Thread(
                target=target, args=(interface,), daemon=True
            )
        else:
            # demo=False 로 불러도 캡처 백엔드가 없으면 합성이다. 요청이 아니라
            # 사실을 기록한다.
            if not demo:
                _log.warning(
                    "[PacketAnalyzer] 실모드를 요청했으나 PyShark·Scapy 가 없어 "
                    "합성 트래픽으로 동작한다 — ML 피처는 origin='demo' 로 기록된다"
                )
            self.source_mode = "demo"
            self.thread = threading.Thread(target=self._demo_loop, daemon=True)

        self.thread.start()
        threading.Thread(target=self._emit_loop, daemon=True).start()

    def stop(self):
        self.running = False

    @staticmethod
    def default_interface(route_table=None):
        """기본 라우트(목적지 0.0.0.0)의 장치명. 없으면 None(=백엔드 기본값).

        route_table: /proc/net/route 내용(테스트용). 기본은 실제 파일을 읽는다.
        """
        try:
            text = route_table if route_table is not None else open("/proc/net/route").read()
        except OSError:
            return None
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "00000000":
                flags = int(parts[3], 16)
                if flags & 0x1:            # RTF_UP
                    return parts[0]
        return None

    def get_stats(self):
        with self._lock:
            stats = dict(self.stats)
            recent = list(self.recent_packets)
        # ML 피처용: 최근 패킷 윈도우 기준 고유 출발지/목적지 포트 수
        stats["unique_src_ips"] = len({p["src_ip"] for p in recent})
        stats["unique_dst_ports"] = len(
            {p["dst_port"] for p in recent if p.get("dst_port")}
        )
        # 소비자(ml_analyst)가 합성/실측을 구분할 수 있어야 한다.
        stats["source_mode"] = self.source_mode
        stats["interface"] = getattr(self, "interface", None)
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
        """실캡처. **한 번 띄운 tshark 를 영원히 두지 않는다.**

        pyshark 는 dumpcap → tshark(PDML) 파이프로 도는데, tshark 는 대화·재조립
        상태를 캡처가 끝날 때까지 들고 있다. 그래서 오래 켜 두면 RSS 가 단조
        증가한다 — 실측 2026-09-12: 약 350pps 로 10시간 뒤 **3.6GB**, 9.7GB 짜리
        WSL 의 가용 메모리가 1.6GB 까지 떨어져 다른 프로세스가 OOM 위험에 놓였다
        (전날 실제로 커널이 여러 프로세스를 죽였다).

        그래서 두 가지 한도로 캡처를 새로 띄운다. 시간(기본 30분)은 정상 상태를
        위한 것이고, RSS 상한(기본 700MB)은 트래픽이 튈 때를 위한 안전망이다.
        교체 사이에 수 백 ms 공백이 생기는데, ML 재학습은 pps·bps 가 0 인 창을
        이미 제외하므로 학습 분포를 오염시키지 않는다.
        """
        while self.running:
            cap = None
            cycle_started = time.time()
            packets = 0
            try:
                # 사이클마다 **새 이벤트 루프**를 이 스레드에 깔아 준다.
                # pyshark 는 루프를 직접 만들지 않고 스레드의 현재 루프를 집어
                # 쓰는데(capture.py `_setup_eventloop`), 앞 사이클에서 닫은 루프를
                # 그대로 집으면 두 번째 캡처가 곧바로 죽는다 — 실제로 그렇게 만들어
                # 첫 재활용 뒤 캡처가 데모로 폴백했다(2026-09-12).
                asyncio.set_event_loop(asyncio.new_event_loop())
                cap = _FdSafeLiveCapture(interface=interface, bpf_filter="ip or arp")
                for pkt in cap.sniff_continuously():
                    if not self.running:
                        break
                    self._process_pyshark_packet(pkt)
                    packets += 1
                    # 한도 확인은 128 패킷마다 — 매 패킷 확인은 그 자체가 비용이다
                    if packets % 128 == 0 and self._capture_should_recycle(cycle_started):
                        break
            except Exception as e:
                _log.warning(f"[PacketAnalyzer] PyShark error: {e} — fallback to demo")
                self.source_mode = "demo"   # 여기부터 나오는 트래픽은 합성이다
                self._demo_loop()
                return
            finally:
                self._close_capture(cap)
            if self.running:
                self.capture_cycles += 1
                _log.info(f"[PacketAnalyzer] 캡처 재활용 #{self.capture_cycles} — "
                          f"{int(time.time() - cycle_started)}초 · {packets:,}패킷 처리")

    def _capture_should_recycle(self, cycle_started):
        """이번 캡처를 접고 새로 띄울 때인가 (시간 초과 또는 메모리 상한)."""
        if time.time() - cycle_started >= self.capture_recycle_seconds:
            return True
        rss = self._capture_rss_mb()
        if rss is not None and rss >= self.capture_max_rss_mb:
            _log.warning(f"[PacketAnalyzer] tshark RSS {rss:,}MB — 상한"
                         f" {self.capture_max_rss_mb:,}MB 도달, 캡처를 새로 띄운다")
            return True
        return False

    def _capture_rss_mb(self):
        """이 프로세스가 띄운 tshark·dumpcap 의 RSS 합(MB). 못 재면 None."""
        if psutil is None:
            return None
        try:
            total = 0
            for child in psutil.Process().children(recursive=True):
                try:
                    if child.name() in ("tshark", "dumpcap"):
                        total += child.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return total // (1024 * 1024)
        except Exception:
            return None

    @staticmethod
    def _close_capture(cap):
        """캡처를 확실히 내린다 — **여기서 실패하면 재활용이 오히려 누수가 된다.**

        tshark·dumpcap 이 남은 채로 새로 띄우면 30분마다 프로세스가 하나씩 쌓인다.
        그래서 예외를 삼키되, 남은 자식이 있으면 마지막에 강제로 정리한다.
        """
        if cap is None:
            return
        # close() 가 목록을 비우므로 **먼저** 붙잡아 둔다.
        procs = list(getattr(cap, "_running_processes", None) or [])
        try:
            cap.close()
        except Exception as e:
            _log.warning(f"[PacketAnalyzer] 캡처 종료 중 오류(무시): {e}")
        # pyshark 는 프로세스를 죽이기만 하고 거기 붙은 파이프(asyncio 서브프로세스
        # 전송)는 닫지 않는다. 루프를 닫아 버리면 그 전송은 영영 안 닫혀
        # **사이클마다 파이프 3개가 샌다**(실측: 4 사이클에 fd 12→22).
        # pyshark 내부 이름이라 버전이 바뀌면 없을 수 있어 전부 방어적으로 만진다.
        for proc in procs:
            transport = getattr(proc, "_transport", None)
            if transport is None:
                continue
            try:
                transport.close()
            except Exception:
                pass
        # pyshark 는 캡처마다 asyncio 이벤트 루프를 하나 만든다. 안 닫으면
        # 재활용할 때마다 루프와 파일 서술자가 쌓인다 — 누수를 고치다 다른
        # 누수를 만드는 셈이 된다.
        loop = getattr(cap, "eventloop", None)
        if loop is not None and not loop.is_closed():
            try:
                # 루프를 잠깐 더 돌린다. pyshark 의 close 는 프로세스를 죽이기만
                # 하고, 그 프로세스에 붙은 파이프는 EOF 콜백이 돌아야 닫힌다.
                # 이걸 건너뛰고 루프를 닫으면 **사이클마다 파이프 3개가 샌다**
                # (실측: 4 사이클에 fd 12→22).
                loop.run_until_complete(asyncio.sleep(0.15))
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass
        if psutil is None:
            return
        try:
            for child in psutil.Process().children(recursive=True):
                try:
                    if child.name() in ("tshark", "dumpcap"):
                        child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            gone, alive = psutil.wait_procs(
                [c for c in psutil.Process().children(recursive=True)
                 if c.name() in ("tshark", "dumpcap")], timeout=3)
            for proc in alive:
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

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
            _log.warning(f"[PacketAnalyzer] Scapy error: {e} — fallback to demo")
            self.source_mode = "demo"   # 여기부터 나오는 트래픽은 합성이다
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
