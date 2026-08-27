"""
취약점 스캐너 — 포트 · 서비스 · CVE 점검

선택한 서버(localhost + ANSIBLE_TARGETS 원격)에 대해:
  1) 열린 TCP 포트 스캔 (connect 스캔 — 읽기 전용, 비파괴)
  2) 배너 그래빙으로 서비스/버전 식별
  3) 알려진 CVE 매핑 (nmap vulners 스크립트 or 내장 휴리스틱 DB)

설계 원칙 (운영 중 자동매매 서버 보호):
  - connect() 스캔만 사용 — SYN/스텔스/스크립트 공격 없음, 비파괴
  - 포트별 짧은 timeout, 동시성 제한으로 대상 부하 최소화
  - nmap 있으면 `-sV` + `vulners`(설치 시)로 정밀 식별, 없으면 파이썬 소켓 fallback
  - nmap/네트워크 불가 시 데모 결과로 동작 (학습·데모용)

CVE 심각도는 데모/휴리스틱 값 — 실제 관제는 nmap+vulners 또는 외부 피드 연동 권장.
"""
import os
import re
import sys
import socket
import shutil
import tempfile
import threading
import subprocess
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed


# 기본 점검 포트 (자주 노출되는 서비스 + 자동매매 대시보드 포트)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5005, 5050,
    5055, 5432, 5601, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 11211, 27017,
]

# 포트 → 서비스 이름 힌트 (배너 못 잡을 때 fallback)
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "http-alt",
    5005: "http-app", 5050: "http-app", 5055: "http-app", 5432: "postgresql",
    5601: "kibana", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9000: "http-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

# 위험 노출 포트 (인터넷에 열려 있으면 그 자체로 지적)
RISKY_EXPOSED = {
    23: ("telnet 평문 원격접속", "high"),
    3389: ("RDP 외부 노출", "high"),
    445: ("SMB 외부 노출", "high"),
    5900: ("VNC 외부 노출", "high"),
    6379: ("Redis 인증 없이 노출 가능", "high"),
    9200: ("Elasticsearch 노출", "medium"),
    11211: ("Memcached 노출(증폭 DDoS 악용)", "medium"),
    27017: ("MongoDB 노출", "high"),
    3306: ("MySQL 외부 노출", "medium"),
    5432: ("PostgreSQL 외부 노출", "medium"),
    2049: ("NFS 노출", "medium"),
}

# 배너 휴리스틱 CVE DB (버전 조건 → CVE). 데모/학습용 — 실제는 vulners 권장.
#   각 항목: (서비스 정규식, 버전추출 정규식, [(조건함수, cve, 심각도, 설명)])
def _ver_lt(parts, ref):
    """버전 튜플 비교: parts < ref 이면 True"""
    for a, b in zip(parts, ref):
        if a != b:
            return a < b
    return len(parts) < len(ref)


def _parse_ver(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:4])


_BANNER_CVE = [
    ("openssh", r"OpenSSH[_/ ](\d+\.\d+(?:p\d+)?)", [
        (lambda v: _ver_lt(v, (9, 8)), "CVE-2024-6387 (regreSSHion)", "high",
         "sshd 사전인증 RCE — 9.8 미만 취약"),
        (lambda v: _ver_lt(v, (8, 5)), "CVE-2021-28041", "medium",
         "ssh-agent 이중해제"),
    ]),
    ("apache", r"Apache[/ ](\d+\.\d+\.\d+)", [
        (lambda v: _ver_lt(v, (2, 4, 59)), "CVE-2024-38476", "high",
         "mod_proxy SSRF/정보노출 — 2.4.59 미만"),
    ]),
    ("nginx", r"nginx[/ ](\d+\.\d+\.\d+)", [
        (lambda v: _ver_lt(v, (1, 21, 0)), "CVE-2021-23017", "high",
         "resolver off-by-one 힙 오버플로"),
    ]),
    ("openssl", r"OpenSSL[/ ](\d+\.\d+\.\d+)", [
        (lambda v: _ver_lt(v, (3, 0, 7)), "CVE-2022-3602/3786", "high",
         "X.509 이메일 검증 버퍼 오버플로"),
    ]),
    ("vsftpd", r"vsftpd (\d+\.\d+\.\d+)", [
        (lambda v: v == (2, 3, 4), "CVE-2011-2523", "high", "vsftpd 2.3.4 백도어"),
    ]),
    ("proftpd", r"ProFTPD (\d+\.\d+\.\d+)", [
        (lambda v: _ver_lt(v, (1, 3, 6)), "CVE-2019-12815", "high",
         "mod_copy 임의 파일복사"),
    ]),
    ("exim", r"Exim (\d+\.\d+)", [
        (lambda v: _ver_lt(v, (4, 92)), "CVE-2019-10149", "high",
         "deliver_message RCE"),
    ]),
]


# 주요 CVE 설명 (한글 요약) — vulners는 CVSS만 주므로 알려진 것에 설명 보강
_CVE_DESC = {
    "CVE-2024-6387": "regreSSHion — sshd 사전인증 RCE (시그널 핸들러 경쟁조건)",
    "CVE-2023-38408": "OpenSSH ssh-agent PKCS#11 원격 코드 실행 (에이전트 포워딩 시)",
    "CVE-2023-28531": "OpenSSH ssh-add 스마트카드 키 제약 우회",
    "CVE-2023-51385": "OpenSSH ProxyCommand 명령 주입 (특수문자 hostname)",
    "CVE-2023-51384": "OpenSSH ssh-agent destination 제약 미적용 (키 노출)",
    "CVE-2023-48795": "Terrapin 공격 — SSH 전송계층 프로토콜 다운그레이드/무결성 우회",
    "CVE-2025-26465": "OpenSSH VerifyHostKeyDNS 활성 시 클라이언트 MITM",
    "CVE-2021-23017": "nginx resolver off-by-one 힙 오버플로 (원격 코드 실행 가능)",
    "CVE-2024-38476": "Apache httpd mod_proxy SSRF/백엔드 정보노출",
    "CVE-2022-3602": "OpenSSL X.509 이메일 검증 스택 버퍼 오버플로 (Punycode)",
    "CVE-2022-3786": "OpenSSL X.509 이메일 검증 버퍼 오버플로 (Punycode)",
    "CVE-2011-2523": "vsftpd 2.3.4 백도어 (스마일리 트리거 → 루트셸)",
    "CVE-2019-12815": "ProFTPD mod_copy 인증 없이 임의 파일 복사",
    "CVE-2019-10149": "Exim deliver_message 원격 코드 실행",
}

# nmap 서비스명/버전 키워드 → apt 패키지 (교차검증용)
_SERVICE_PKG = [
    ("openssh", "openssh-server"), ("ssh", "openssh-server"),
    ("nginx", "nginx"), ("apache", "apache2"), ("httpd", "apache2"),
    ("openssl", "openssl"), ("vsftpd", "vsftpd"), ("proftpd", "proftpd-basic"),
    ("exim", "exim4"), ("postfix", "postfix"), ("mysql", "mysql-server"),
    ("mariadb", "mariadb-server"), ("postgresql", "postgresql"),
    ("redis", "redis-server"), ("bind", "bind9"), ("dovecot", "dovecot-core"),
]


class VulnScanner:
    def __init__(self, socketio, config=None):
        self.socketio = socketio
        self.config = config or {}
        self.running = False
        self._lock = threading.Lock()
        self._scanning = False

        self.nmap_bin = shutil.which("nmap")
        self.ansible_bin = self._find_ansible()   # 원격 apt 교차검증용
        self.hosts = self._load_hosts()
        # 포트 목록: .env VULN_SCAN_PORTS="22,80,443" 로 재정의 가능
        self.ports = self._load_ports()

        self.results = {}          # host_id -> {host, addr, ports:[...], scanned}
        self.history = deque(maxlen=30)
        self.stats = {
            "mode": "off",
            "hosts": len(self.hosts),
            "open_ports": 0,
            "vulns": 0,
            "critical": 0,
            "high": 0,
            "last_scan": None,
            "nmap": bool(self.nmap_bin),
            "ansible": bool(self.ansible_bin),
            "scanning": False,
        }

    # ------------------------------------------------------------------ #
    #  호스트 / 포트 인벤토리
    # ------------------------------------------------------------------ #

    def _load_hosts(self):
        """patch_manager 와 동일한 대상 인벤토리 (localhost + ANSIBLE_TARGETS)."""
        hosts = [{"id": "localhost", "name": "이 서버(localhost)", "addr": "127.0.0.1",
                  "conn": "local"}]
        raw = self.config.get("ANSIBLE_TARGETS", "") or ""
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, addr = part.split("=", 1)
            name, addr = name.strip(), addr.strip()
            if not addr:
                continue
            host = addr.split("@", 1)[1] if "@" in addr else addr
            hosts.append({"id": addr, "name": name, "addr": host, "conn": "ssh"})
        return hosts

    def _load_ports(self):
        raw = self.config.get("VULN_SCAN_PORTS", "") or ""
        ports = []
        for tok in raw.split(","):
            tok = tok.strip()
            if tok.isdigit():
                ports.append(int(tok))
        return ports or list(DEFAULT_PORTS)

    def _hosts_by_id(self, ids):
        if not ids:
            return list(self.hosts)
        idset = set(ids)
        sel = [h for h in self.hosts if h["id"] in idset]
        return sel or list(self.hosts)

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        self._demo = demo
        with self._lock:
            # 온디맨드 스캐너는 대상이 응답하면 항상 실측 → 전역 DEMO_MODE 무관하게 real.
            # (응답 없는 대상만 데모 샘플로 표시)
            self.stats["mode"] = "real"
        n = "nmap 있음(정밀)" if self.nmap_bin else "nmap 미설치(소켓 스캔)"
        a = "ansible 있음(원격 교차검증)" if self.ansible_bin else "ansible 미설치(원격 미확인)"
        print(f"[VulnScan] 취약점 스캐너 준비 — {'데모' if demo else '실측'}, {n}, {a}, "
              f"대상 {len(self.hosts)}대 · 포트 {len(self.ports)}개")

    def stop(self):
        self.running = False

    # ------------------------------------------------------------------ #
    #  스캔 진입점
    # ------------------------------------------------------------------ #

    def scan(self, host_ids=None):
        """선택 호스트를 백그라운드로 스캔. 즉시 상태 반환(비동기)."""
        with self._lock:
            if self._scanning:
                return {"status": "busy", "msg": "이미 스캔 중입니다."}
            self._scanning = True
            self.stats["scanning"] = True
        sel = self._hosts_by_id(host_ids)
        threading.Thread(target=self._run_scan, args=(sel,), daemon=True).start()
        self._emit_status()
        return {"status": "started", "hosts": [h["name"] for h in sel]}

    def _run_scan(self, sel):
        try:
            for h in sel:
                res = self._scan_host(h)
                with self._lock:
                    self.results[h["id"]] = res
                self._emit_host(res)
            self._recount()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with self._lock:
                self.stats["last_scan"] = ts
                self.history.appendleft({
                    "ts": ts, "hosts": len(sel),
                    "open_ports": self.stats["open_ports"],
                    "vulns": self.stats["vulns"],
                })
        except Exception as e:
            print(f"[VulnScan] 스캔 오류: {e}")
        finally:
            with self._lock:
                self._scanning = False
                self.stats["scanning"] = False
            self._emit_status()

    def _scan_host(self, host):
        addr = host["addr"]
        # 온디맨드 스캔은 대상이 응답하면 항상 실제 스캔(비파괴 connect).
        # 전역 DEMO_MODE 와 무관 — 사용자가 명시적으로 요청한 실측이므로.
        # 대상이 응답하지 않을 때만 데모 결과로 fallback.
        if not self._reachable(addr):
            ports = self._demo_ports(host)
        elif self.nmap_bin:
            ports = self._nmap_scan(addr)
            if ports is None:
                ports = self._socket_scan(addr)
        else:
            ports = self._socket_scan(addr)
        self._cross_validate(host, ports)
        return {
            "id": host["id"], "host": host["name"], "addr": addr,
            "scanned": datetime.now().strftime("%H:%M:%S"),
            "ports": ports,
            "open": len(ports),
            "vulns": sum(len(p.get("cves", [])) for p in ports),
        }

    # ------------------------------------------------------------------ #
    #  교차 검증 — 버전기반 CVE를 실제 apt 패치 상태와 대조 (정탐/오탐)
    # ------------------------------------------------------------------ #

    def _cross_validate(self, host, ports):
        """버전 스캐너(vulners)는 업스트림 버전만 보고 CVE를 매김 → Ubuntu 백포트
        패치를 반영 못 해 오탐 다발. 실제 설치 패키지의 apt 상태와 대조해 판정.
        localhost 는 직접 apt/dpkg, 원격은 ansible(-m shell, 읽기전용)로 조회."""
        if not any(p.get("cves") for p in ports):
            return   # CVE 없으면 교차검증 불필요
        if host["conn"] == "local":
            upgradable = self._apt_upgradable()
            installed = None   # 패키지별 개별 조회
            remote = False
        else:
            status = self._remote_apt_status(host)   # (upgradable, {pkg:ver}) or None
            if status is None:
                note = ("원격 apt 교차검증 실패 — ansible 미설치 또는 SSH 연결 불가"
                        if not self.ansible_bin else "원격 apt 조회 실패(SSH 연결/권한 확인)")
                for p in ports:
                    if p.get("cves"):
                        p["verdict"] = {"state": "unknown", "note": note}
                return
            upgradable, installed = status
            remote = True

        for p in ports:
            if not p.get("cves"):
                continue
            pkg = self._service_to_pkg(p)
            if not pkg:
                p["verdict"] = {"state": "unknown", "note": "패키지 매핑 불가"}
                continue
            inst = installed.get(pkg) if remote else self._installed_version(pkg)
            p["verdict"] = self._verdict_for(pkg, inst, upgradable, remote)

    def _verdict_for(self, pkg, installed, upgradable, remote=False):
        """패키지의 설치버전 + 업그레이드 대기 여부로 정탐/오탐 판정."""
        src = " (원격)" if remote else ""
        if not installed:
            return {"state": "unknown", "pkg": pkg,
                    "note": f"{pkg} 미설치/조회불가{src}"}
        if pkg in upgradable:
            return {"state": "vulnerable", "pkg": pkg, "installed": installed,
                    "candidate": upgradable[pkg],
                    "note": f"보안 업데이트 대기 중{src} — 실제 취약(정탐 유력). 패치 필요."}
        if re.search(r"ubuntu|deb|build", installed, re.I):
            return {"state": "patched", "pkg": pkg, "installed": installed,
                    "note": f"배포판 최신 + 백포트 리비전{src} — 버전기반 CVE는 "
                            "이미 패치됐을 가능성 높음(오탐 유력)."}
        return {"state": "unknown", "pkg": pkg, "installed": installed,
                "note": f"업그레이드 대기 없음(최신)이나 백포트 표식 없음{src} — 수동 확인 권장."}

    def _apt_upgradable(self):
        """apt list --upgradable → {패키지: 후보버전}. 읽기 전용(안전)."""
        try:
            r = subprocess.run(["apt", "list", "--upgradable"],
                               capture_output=True, text=True, timeout=30)
            return self._parse_upgradable(r.stdout)
        except Exception:
            return {}

    def _parse_upgradable(self, text):
        out = {}
        for line in (text or "").splitlines():
            m = re.match(r"^(\S+?)/\S+\s+(\S+)\s", line.strip())
            if m:
                out[m.group(1)] = m.group(2)
        return out

    def _installed_version(self, pkg):
        try:
            r = subprocess.run(["dpkg-query", "-W", "-f=${Version}", pkg],
                               capture_output=True, text=True, timeout=10)
            v = (r.stdout or "").strip()
            return v or None
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    #  원격 apt 상태 조회 (ansible -m shell, 읽기 전용)
    # ------------------------------------------------------------------ #

    def _find_ansible(self):
        """PATH + venv bin 에서 ansible 탐색 (./venv/bin/python 실행 시 PATH 누락 대비)."""
        found = shutil.which("ansible")
        if found:
            return found
        cand = os.path.join(os.path.dirname(sys.executable), "ansible")
        return cand if os.path.exists(cand) else None

    def _write_inventory(self, host):
        """단일 원격 호스트용 임시 Ansible 인벤토리(INI) → 경로 반환."""
        addr = host["addr"]
        if addr in ("localhost", "127.0.0.1"):
            line = "localhost ansible_connection=local"
        elif "@" in host.get("id", "") or "@" in addr:
            raw = host.get("id", addr)
            user, h = raw.split("@", 1) if "@" in raw else (None, addr)
            line = f"{h} ansible_user={user}" if user else h
        else:
            line = addr
        fd, path = tempfile.mkstemp(prefix="soc_vscan_inv_", suffix=".ini")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("[targets]\n" + line + "\n")
        return path

    def _remote_apt_status(self, host):
        """원격 호스트에 ansible -m shell 로 apt 상태 조회 → (upgradable, {pkg:ver}) or None.
        읽기 전용 명령만 실행(자동매매 서버 안전)."""
        if not self.ansible_bin:
            return None
        inv = self._write_inventory(host)
        try:
            shell = ("apt list --upgradable 2>/dev/null; echo '===INSTALLED==='; "
                     "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null")
            cmd = [self.ansible_bin, "targets", "-i", inv, "-m", "shell", "-a", shell]
            env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING="False")
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
            # 마커가 있으면 성공(연결·실행됨). 없으면 연결 실패로 간주.
            return self._parse_remote_apt(r.stdout)
        except Exception as e:
            print(f"[VulnScan] 원격 apt 조회 실패({host['name']}): {e}")
            return None
        finally:
            try:
                os.remove(inv)
            except OSError:
                pass

    def _parse_remote_apt(self, output):
        """ansible shell 출력 → (upgradable dict, installed dict). 마커로 구간 분리."""
        if "===INSTALLED===" not in output:
            return None
        up_part, inst_part = output.split("===INSTALLED===", 1)
        upgradable = self._parse_upgradable(up_part)
        installed = {}
        for line in inst_part.splitlines():
            m = re.match(r"^([a-z0-9][a-z0-9.+-]+)\s+(\S+)$", line.strip(), re.I)
            if m:
                installed[m.group(1)] = m.group(2)
        return upgradable, installed

    def _service_to_pkg(self, port):
        text = f"{port.get('service', '')} {port.get('version', '')}".lower()
        for key, pkg in _SERVICE_PKG:
            if key in text:
                return pkg
        return None

    def _reachable(self, addr):
        """대상 자체가 응답 가능한지 아주 짧게 확인 (하나라도 열려있으면 실스캔)."""
        for p in (22, 80, 443, 5055):
            try:
                with socket.create_connection((addr, p), timeout=0.4):
                    return True
            except OSError:
                continue
        return False

    # ------------------------------------------------------------------ #
    #  소켓 기반 스캔 (nmap 없을 때)
    # ------------------------------------------------------------------ #

    def _socket_scan(self, addr):
        open_ports = []

        def probe(port):
            try:
                with socket.create_connection((addr, port), timeout=0.8) as s:
                    banner = self._grab_banner(s, port)
                return port, banner
            except OSError:
                return port, None

        with ThreadPoolExecutor(max_workers=32) as ex:
            futs = {ex.submit(probe, p): p for p in self.ports}
            for fut in as_completed(futs):
                port, banner = fut.result()
                if banner is None:
                    continue
                open_ports.append(self._build_port(port, banner))
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def _grab_banner(self, s, port):
        try:
            s.settimeout(1.0)
            if port in (80, 8080, 8000, 3000, 5000, 5005, 5050, 5055, 9000, 5601):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(256)
            return data.decode("latin-1", "ignore").strip()
        except OSError:
            return ""

    def _build_port(self, port, banner):
        service = PORT_SERVICE.get(port, "unknown")
        version = ""
        # HTTP Server 헤더
        m = re.search(r"Server:\s*([^\r\n]+)", banner, re.I)
        if m:
            version = m.group(1).strip()
        elif banner:
            version = banner.split("\n")[0][:60]
        cves = self._match_cves(banner or version)
        findings = []
        if port in RISKY_EXPOSED:
            desc, sev = RISKY_EXPOSED[port]
            findings.append({"type": "exposure", "severity": sev, "desc": desc})
        return {
            "port": port, "service": service, "version": version,
            "cves": cves, "findings": findings,
            "severity": self._port_severity(cves, findings),
        }

    def _match_cves(self, text):
        if not text:
            return []
        low = text.lower()
        out = []
        for key, verre, rules in _BANNER_CVE:
            if key not in low:
                continue
            m = re.search(verre, text, re.I)
            if not m:
                continue
            v = _parse_ver(m.group(1))
            for cond, cve, sev, desc in rules:
                try:
                    if cond(v):
                        out.append({"cve": cve, "severity": sev, "desc": desc})
                except Exception:
                    continue
        return out

    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _dedup_cves(self, cves):
        """같은 CVE 번호는 하나로(최고 심각도 유지). CVE-2024-6387 (regreSSHion) 처럼
        접미사가 붙어도 번호 기준으로 병합."""
        best = {}
        for c in cves:
            m = re.search(r"CVE-\d{4}-\d+", c["cve"])
            key = m.group(0) if m else c["cve"]
            cur = best.get(key)
            if cur is None or self._SEV_RANK.get(c["severity"], 0) > self._SEV_RANK.get(cur["severity"], 0):
                best[key] = c
        # 심각도 높은 순 정렬
        return sorted(best.values(),
                      key=lambda c: -self._SEV_RANK.get(c["severity"], 0))

    def _port_severity(self, cves, findings):
        sevs = [c["severity"] for c in cves] + [f["severity"] for f in findings]
        if "critical" in sevs:
            return "critical"
        if "high" in sevs:
            return "high"
        if "medium" in sevs:
            return "medium"
        return "low" if sevs else "info"

    # ------------------------------------------------------------------ #
    #  nmap 기반 스캔 (있을 때 — -sV 서비스/버전, vulners 있으면 CVE)
    # ------------------------------------------------------------------ #

    def _nmap_scan(self, addr):
        ports_arg = ",".join(str(p) for p in self.ports)
        has_vulners = os.path.exists("/usr/share/nmap/scripts/vulners.nse")
        cmd = [self.nmap_bin, "-sT", "-sV", "-Pn", "-T4",
               "-p", ports_arg, "--open", "-oX", "-", addr]
        if has_vulners:
            cmd[4:4] = ["--script", "vulners", "--script-args", "mincvss=5.0"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if r.returncode != 0 and not r.stdout:
                return None
            return self._parse_nmap_xml(r.stdout)
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"[VulnScan] nmap 실패: {e}")
            return None

    def _parse_nmap_xml(self, xml):
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        out = []
        for port_el in root.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            port = int(port_el.get("portid"))
            svc = port_el.find("service")
            service = svc.get("name") if svc is not None else PORT_SERVICE.get(port, "unknown")
            version = ""
            if svc is not None:
                version = " ".join(x for x in (svc.get("product"), svc.get("version")) if x)
            cves = []
            for script in port_el.iter("script"):
                if script.get("id") != "vulners":
                    continue
                # vulners 출력: "\tCVE-2023-38408\t9.8\thttps://vulners.com/..."
                # URL 앵커로 CVSS 오탐(URL 내 숫자 등) 방지
                for cid, score in re.findall(
                        r"(CVE-\d{4}-\d+)\s+([\d.]+)\s+https?://", script.get("output", "")):
                    try:
                        cvss = float(score)
                    except ValueError:
                        continue
                    if not (0 <= cvss <= 10):        # 이상값 제거
                        continue
                    sev = "critical" if cvss >= 9 else "high" if cvss >= 7 else \
                          "medium" if cvss >= 4 else "low"
                    base = _CVE_DESC.get(cid)
                    desc = f"{base} · CVSS {cvss}" if base else f"CVSS {cvss}"
                    cves.append({"cve": cid, "severity": sev, "desc": desc})
            # 배너 휴리스틱도 보강 후 CVE 중복 제거(최고 심각도 유지)
            cves += self._match_cves(f"{service} {version}")
            cves = self._dedup_cves(cves)
            findings = []
            if port in RISKY_EXPOSED:
                desc, sev = RISKY_EXPOSED[port]
                findings.append({"type": "exposure", "severity": sev, "desc": desc})
            out.append({
                "port": port, "service": service, "version": version.strip(),
                "cves": cves, "findings": findings,
                "severity": self._port_severity(cves, findings),
            })
        out.sort(key=lambda x: x["port"])
        return out

    # ------------------------------------------------------------------ #
    #  데모 결과
    # ------------------------------------------------------------------ #

    def _demo_ports(self, host):
        base = [
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1 Ubuntu",
             "cves": [{"cve": "CVE-2024-6387 (regreSSHion)", "severity": "high",
                       "desc": "sshd 사전인증 RCE — 9.8 미만 취약"}],
             "findings": []},
            {"port": 80, "service": "http", "version": "nginx 1.18.0",
             "cves": [{"cve": "CVE-2021-23017", "severity": "high",
                       "desc": "resolver off-by-one 힙 오버플로"}],
             "findings": []},
            {"port": 443, "service": "https", "version": "nginx 1.18.0 (OpenSSL 3.0.2)",
             "cves": [], "findings": []},
            {"port": 5055, "service": "http-app", "version": "Werkzeug/Flask (SOC 대시보드)",
             "cves": [], "findings": []},
        ]
        # 자동매매 원격 호스트는 노출 포트 이슈 하나 더 (데모)
        if host["conn"] == "ssh":
            base.append(
                {"port": 6379, "service": "redis", "version": "Redis 6.2.6",
                 "cves": [], "findings": [{"type": "exposure", "severity": "high",
                          "desc": "Redis 인증 없이 노출 가능"}]})
        for p in base:
            p["demo"] = True
            p["severity"] = self._port_severity(p["cves"], p["findings"])
        return base

    # ------------------------------------------------------------------ #
    #  집계 / 조회 / emit
    # ------------------------------------------------------------------ #

    def _recount(self):
        with self._lock:
            open_ports = vulns = crit = high = 0
            for res in self.results.values():
                for p in res["ports"]:
                    open_ports += 1
                    for c in p.get("cves", []):
                        vulns += 1
                        if c["severity"] == "critical":
                            crit += 1
                        elif c["severity"] == "high":
                            high += 1
                    for f in p.get("findings", []):
                        vulns += 1
                        if f["severity"] == "critical":
                            crit += 1
                        elif f["severity"] == "high":
                            high += 1
            self.stats.update(open_ports=open_ports, vulns=vulns,
                              critical=crit, high=high)

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "hosts": list(self.hosts),
                "ports": list(self.ports),
                "nmap_path": self.nmap_bin,
                "results": [self.results[h["id"]] for h in self.hosts
                            if h["id"] in self.results],
                "history": list(self.history)[:15],
            }

    def _emit_host(self, res):
        try:
            self.socketio.emit("vulnscan_host", res)
        except Exception:
            pass

    def _emit_status(self):
        try:
            with self._lock:
                self.socketio.emit("vulnscan_status", {"stats": dict(self.stats)})
        except Exception:
            pass
