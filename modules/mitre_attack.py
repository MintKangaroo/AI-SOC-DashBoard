"""
MITRE ATT&CK 매트릭스 모듈
- 14개 Tactic × 대표 Technique 매핑
- 탐지 이벤트 → ATT&CK 기법 자동 매핑
- 매트릭스 셀별 탐지 카운트 집계
"""
import threading
from collections import defaultdict
from datetime import datetime


# ─────────────────────────────────────────
#  MITRE ATT&CK Enterprise Matrix (요약)
#  14 Tactics × 대표 Techniques
# ─────────────────────────────────────────
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance",         "ko": "정찰"},
    {"id": "TA0042", "name": "Resource Development",   "ko": "자원 개발"},
    {"id": "TA0001", "name": "Initial Access",         "ko": "초기 접근"},
    {"id": "TA0002", "name": "Execution",              "ko": "실행"},
    {"id": "TA0003", "name": "Persistence",            "ko": "지속성"},
    {"id": "TA0004", "name": "Privilege Escalation",   "ko": "권한 상승"},
    {"id": "TA0005", "name": "Defense Evasion",        "ko": "방어 회피"},
    {"id": "TA0006", "name": "Credential Access",      "ko": "자격증명 접근"},
    {"id": "TA0007", "name": "Discovery",              "ko": "탐색"},
    {"id": "TA0008", "name": "Lateral Movement",       "ko": "내부 이동"},
    {"id": "TA0009", "name": "Collection",             "ko": "수집"},
    {"id": "TA0011", "name": "Command and Control",    "ko": "명령 제어"},
    {"id": "TA0010", "name": "Exfiltration",           "ko": "유출"},
    {"id": "TA0040", "name": "Impact",                 "ko": "영향"},
]

TECHNIQUES = {
    "TA0043": [
        {"id": "T1595", "name": "Active Scanning",                "ko": "능동 스캔"},
        {"id": "T1590", "name": "Gather Victim Network Info",     "ko": "네트워크 정보 수집"},
        {"id": "T1046", "name": "Network Service Discovery",      "ko": "네트워크 서비스 탐색"},
    ],
    "TA0042": [
        {"id": "T1583", "name": "Acquire Infrastructure",         "ko": "인프라 확보"},
        {"id": "T1588", "name": "Obtain Capabilities",            "ko": "공격 도구 획득"},
    ],
    "TA0001": [
        {"id": "T1190", "name": "Exploit Public-Facing App",      "ko": "공개 서비스 익스플로잇"},
        {"id": "T1133", "name": "External Remote Services",       "ko": "외부 원격 서비스"},
        {"id": "T1566", "name": "Phishing",                       "ko": "피싱"},
        {"id": "T1078", "name": "Valid Accounts",                 "ko": "유효 계정 사용"},
    ],
    "TA0002": [
        {"id": "T1059", "name": "Command and Scripting Interpreter","ko": "명령/스크립트 실행"},
        {"id": "T1053", "name": "Scheduled Task/Job",             "ko": "예약 작업"},
        {"id": "T1204", "name": "User Execution",                 "ko": "사용자 실행"},
    ],
    "TA0003": [
        {"id": "T1547", "name": "Boot or Logon Autostart",        "ko": "부팅/로그온 자동실행"},
        {"id": "T1546", "name": "Event Triggered Execution",      "ko": "이벤트 트리거 실행"},
        {"id": "T1136", "name": "Create Account",                 "ko": "계정 생성"},
        # Sigma 룰(웹셸)·퍼플팀 시나리오가 이미 T1505.003 을 가리키는데 매트릭스에
        # 칸이 없어 탐지돼도 표시되지 않았다 — 커버리지 자가 진단이 찾아냈다.
        {"id": "T1505", "name": "Server Software Component",      "ko": "서버 소프트웨어 컴포넌트(웹셸)"},
    ],
    "TA0004": [
        {"id": "T1068", "name": "Exploitation for Priv Esc",      "ko": "권한상승 익스플로잇"},
        {"id": "T1055", "name": "Process Injection",              "ko": "프로세스 인젝션"},
    ],
    "TA0005": [
        {"id": "T1027", "name": "Obfuscated Files or Info",       "ko": "난독화"},
        {"id": "T1070", "name": "Indicator Removal",              "ko": "흔적 제거"},
        {"id": "T1562", "name": "Impair Defenses",                "ko": "보안 기능 무력화"},
    ],
    "TA0006": [
        {"id": "T1003", "name": "OS Credential Dumping",          "ko": "OS 자격증명 덤프"},
        {"id": "T1110", "name": "Brute Force",                    "ko": "무차별 대입"},
        {"id": "T1555", "name": "Credentials from Password Stores","ko": "패스워드 저장소"},
    ],
    "TA0007": [
        {"id": "T1083", "name": "File and Directory Discovery",   "ko": "파일/디렉터리 탐색"},
        {"id": "T1057", "name": "Process Discovery",              "ko": "프로세스 탐색"},
        {"id": "T1018", "name": "Remote System Discovery",        "ko": "원격 시스템 탐색"},
    ],
    "TA0008": [
        {"id": "T1021", "name": "Remote Services",                "ko": "원격 서비스"},
        {"id": "T1570", "name": "Lateral Tool Transfer",          "ko": "도구 이동"},
    ],
    "TA0009": [
        {"id": "T1005", "name": "Data from Local System",         "ko": "로컬 데이터 수집"},
        {"id": "T1056", "name": "Input Capture",                  "ko": "입력 캡처"},
    ],
    "TA0011": [
        {"id": "T1071", "name": "Application Layer Protocol",     "ko": "응용계층 프로토콜 C2"},
        {"id": "T1572", "name": "Protocol Tunneling",             "ko": "프로토콜 터널링"},
        {"id": "T1105", "name": "Ingress Tool Transfer",          "ko": "도구 반입"},
        {"id": "T1571", "name": "Non-Standard Port",              "ko": "비표준 포트 통신"},
    ],
    "TA0010": [
        {"id": "T1041", "name": "Exfil Over C2 Channel",          "ko": "C2 채널로 유출"},
        {"id": "T1048", "name": "Exfil Over Alternative Protocol","ko": "대체 프로토콜로 유출"},
    ],
    "TA0040": [
        {"id": "T1498", "name": "Network Denial of Service",      "ko": "네트워크 DoS"},
        {"id": "T1499", "name": "Endpoint Denial of Service",     "ko": "엔드포인트 DoS"},
        {"id": "T1486", "name": "Data Encrypted for Impact",      "ko": "랜섬웨어 암호화"},
        # 위와 같은 사유 — 크립토마이너 Sigma 룰·퍼플팀 시나리오의 대상 기법
        {"id": "T1496", "name": "Resource Hijacking",             "ko": "자원 탈취(크립토마이닝)"},
    ],
}


# ─────────────────────────────────────────
#  이벤트 → ATT&CK 매핑 규칙
# ─────────────────────────────────────────
#   (threat_type 또는 sysmon event) → [(tactic_id, technique_id), ...]
THREAT_MAPPING = {
    "DDOS":            [("TA0040", "T1498")],
    "PORT_SCAN":       [("TA0043", "T1046"), ("TA0007", "T1018")],
    "BRUTE_FORCE":     [("TA0006", "T1110")],
    "MALWARE_BEACON":  [("TA0011", "T1071"), ("TA0011", "T1105")],
    "MALWARE_FILE":    [("TA0005", "T1027"), ("TA0002", "T1204")],
    "DATA_EXFIL":      [("TA0010", "T1048"), ("TA0010", "T1041")],
    "ARP_SPOOFING":    [("TA0008", "T1021")],
    "DNS_TUNNELING":   [("TA0011", "T1572")],
    "ANOMALY":         [("TA0043", "T1595")],
    "MALWARE_C2":      [("TA0011", "T1071")],
    "METASPLOIT":      [("TA0002", "T1059"), ("TA0011", "T1071"),
                        ("TA0011", "T1571"), ("TA0004", "T1055")],
    "METERPRETER":     [("TA0011", "T1071"), ("TA0002", "T1059"),
                        ("TA0004", "T1055")],
    "LSASS_DUMP":      [("TA0006", "T1003")],
    "PROC_INJECTION":  [("TA0004", "T1055"), ("TA0005", "T1055")],
    "PS_ENCODED":      [("TA0002", "T1059"), ("TA0005", "T1027")],
}


# ─────────────────────────────────────────
#  Technique별 방어 권고
# ─────────────────────────────────────────
DEFENSE_RECOMMENDATIONS = {
    "T1595": ["외부 노출 서비스 최소화", "포트 스캔 탐지 IDS/IPS 활성화", "WAF 도입"],
    "T1590": ["WHOIS/DNS 정보 노출 최소화", "외부 정찰 로그 모니터링"],
    "T1046": ["내부망 세분화(Micro-segmentation)", "포트스캔 탐지 룰 강화"],
    "T1190": ["공개 서비스 주기적 패치", "WAF 및 RASP 적용", "취약점 스캔 정례화"],
    "T1133": ["VPN/RDP 다중인증 필수", "IP 화이트리스트", "세션 타임아웃 강제"],
    "T1566": ["메일 보안 게이트웨이(SEG)", "첨부파일 샌드박스", "사용자 피싱 훈련"],
    "T1078": ["MFA 전면 적용", "계정 이상행위 탐지(UEBA)", "관리자 계정 분리"],
    "T1059": ["스크립트 실행 로깅(PowerShell Transcription)", "AppLocker/WDAC",
              "ConstrainedLanguageMode 적용"],
    "T1053": ["예약 작업 생성 모니터링(Event 4698)", "관리자 외 작업 생성 차단"],
    "T1204": ["EDR의 사용자 실행 차단 정책", "매크로 비활성화"],
    "T1547": ["레지스트리 Run 키 모니터링(Sysmon 12/13)", "시작 폴더 감시"],
    "T1546": ["WMI 이벤트 구독 모니터링(Sysmon 19/20/21)"],
    "T1136": ["신규 계정 생성 이벤트(4720) 경보", "서비스 계정 표준화"],
    "T1068": ["OS/드라이버 보안 패치", "KASLR·SMEP/SMAP 활성화"],
    "T1055": ["프로세스 인젝션 탐지(Sysmon 8)", "CreateRemoteThread 차단 EDR 정책",
              "LSASS 보호(RunAsPPL)"],
    "T1027": ["AMSI 통합", "난독화 패턴 탐지", "PS 스크립트 로깅"],
    "T1070": ["이벤트 로그 원격 전달(WEF/Sysmon)", "로그 변조 탐지"],
    "T1562": ["EDR Tamper Protection", "보안 서비스 중지 이벤트 경보"],
    "T1003": ["LSASS 보호(RunAsPPL)", "Credential Guard 활성화",
              "Sysmon 10 masks 0x1410/0x143a 경보"],
    "T1110": ["계정 잠금 정책", "로그인 실패 임계 경보", "MFA 강제"],
    "T1555": ["브라우저 자격증명 보호", "DPAPI 감사"],
    "T1083": ["파일시스템 감사 로그", "민감 디렉터리 읽기 이벤트"],
    "T1057": ["프로세스 열거 API 감시", "EDR 행위 탐지"],
    "T1018": ["내부 DNS/ARP 스캔 모니터링", "Honeypot 설치"],
    "T1021": ["RDP/SMB/WinRM 로그 집계", "관리자 Jump Server 사용 강제"],
    "T1570": ["SMB/관리자 공유 파일 복사 감시", "PsExec 차단"],
    "T1005": ["파일 접근 DLP", "민감 폴더 접근 경보"],
    "T1056": ["키로거 방지 EDR", "커널 레벨 입력 훅 감시"],
    "T1071": ["egress 방화벽 화이트리스트", "C2 도메인 IOC 차단",
              "TLS 인스펙션"],
    "T1572": ["DNS 트래픽 볼륨/엔트로피 분석", "IDS 터널링 룰"],
    "T1105": ["내부 → 외부 파일 다운로드 감시", "URL 평판 차단"],
    "T1571": ["비표준 포트 egress 차단(4444/5555/1337 등)",
              "방화벽 화이트리스트 정책 강화"],
    "T1041": ["DLP", "대용량 outbound 트래픽 경보"],
    "T1048": ["비표준 프로토콜 outbound 탐지", "DNS 응답 크기 모니터링"],
    "T1498": ["CDN/스크러버(Anti-DDoS) 계약", "Rate-Limit 룰", "Anycast 적용"],
    "T1499": ["WAF 리소스 소진 룰", "서버 리소스 모니터링"],
    "T1486": ["오프라인 백업(3-2-1)", "쉐도우 카피 보호", "EDR 행위 탐지(대량 암호화)"],
    "T1583": ["도메인·호스팅 abuse 신고 채널 확보"],
    "T1588": ["CVE 대응 체계", "악성 도구 IOC 피드"],
}


# ─────────────────────────────────────────
#  Technique 요약 설명
# ─────────────────────────────────────────
TECHNIQUE_DESCRIPTIONS = {
    "T1595": "공격자가 대상의 인프라를 능동적으로 스캔(포트스캔·취약점 스캔)하여 공격 경로를 찾는 단계.",
    "T1590": "WHOIS·DNS·CDN 정보 등 공격 대상 네트워크 관련 오픈 정보를 수집한다.",
    "T1046": "네트워크 내 열려있는 포트/서비스를 확인하여 추가 공격 대상 식별.",
    "T1190": "외부 노출된 웹/서비스의 취약점을 이용해 최초 침투에 성공.",
    "T1133": "VPN·RDP 등 외부 원격 서비스 자격증명으로 네트워크에 진입.",
    "T1566": "이메일·SMS 등으로 악성 첨부/링크를 전달하는 피싱 기법.",
    "T1078": "유효한 계정 자격증명으로 합법 사용자처럼 접근.",
    "T1059": "cmd/PowerShell/bash 등 명령·스크립트 해석기를 통한 코드 실행. Metasploit 페이로드 실행의 대표 기법.",
    "T1053": "스케줄드 태스크(작업 스케줄러/cron) 등록을 통한 실행·지속성.",
    "T1204": "사용자가 직접 악성 파일/링크를 실행하도록 유도.",
    "T1547": "Run 키·시작 폴더 등 부팅/로그온 시 자동 실행 항목 추가.",
    "T1546": "WMI 이벤트 구독·특정 이벤트 발생 시 코드 실행.",
    "T1136": "로컬/도메인 계정을 생성하여 지속성 확보.",
    "T1068": "커널/OS 취약점 익스플로잇으로 SYSTEM 권한 획득.",
    "T1055": "정상 프로세스의 메모리 공간에 악성 코드를 주입(CreateRemoteThread 등). Meterpreter migrate 기법 해당.",
    "T1027": "Base64/XOR/패킹 등으로 페이로드를 난독화하여 탐지 회피.",
    "T1070": "이벤트 로그·파일 흔적을 삭제해 포렌식 회피.",
    "T1562": "백신·EDR·방화벽 서비스를 중지시키거나 예외 등록.",
    "T1003": "LSASS 메모리 덤프 등으로 OS 자격증명(해시·평문 암호) 탈취. mimikatz/Meterpreter hashdump 해당.",
    "T1110": "암호 사전 공격·크리덴셜 스터핑으로 계정 탈취.",
    "T1555": "브라우저·키링 등 패스워드 저장소에서 자격증명 추출.",
    "T1083": "파일/디렉터리 구조를 열거해 관심 데이터 탐색.",
    "T1057": "실행 중 프로세스 목록을 수집해 보안 제품 확인 등 수행.",
    "T1018": "내부망 호스트를 탐색(net view·ping 스윕 등).",
    "T1021": "RDP·SMB·WinRM 등으로 내부 다른 호스트로 이동.",
    "T1570": "내부 호스트 간에 도구/페이로드를 복제·전송.",
    "T1005": "로컬 시스템의 민감 파일(문서·DB)을 수집.",
    "T1056": "키보드·클립보드 입력을 캡처하여 자격증명·데이터 탈취.",
    "T1071": "HTTP(S)·DNS 등 정상 프로토콜을 C2 통신 채널로 남용. Meterpreter reverse_https 해당.",
    "T1572": "C2 트래픽을 정상 프로토콜 안으로 터널링(DNS·ICMP 등).",
    "T1105": "C2로부터 추가 도구/페이로드를 다운로드.",
    "T1571": "표준 포트 외(예: 4444·5555·1337)로 C2 통신. Metasploit 기본 페이로드 포트 특징.",
    "T1041": "기 확보된 C2 채널을 통해 수집 데이터 유출.",
    "T1048": "FTP·DNS·ICMP 등 대체 프로토콜로 데이터 유출.",
    "T1498": "대규모 트래픽 flooding으로 네트워크 가용성 침해.",
    "T1499": "애플리케이션 자원 소진형 DoS(웹 슬로우로리스·쿼리 폭주).",
    "T1486": "랜섬웨어로 파일 암호화 및 금품 요구.",
    "T1583": "공격용 도메인·서버 등 인프라 구축.",
    "T1588": "악성 도구·CVE·스트레서·인증서 등 확보.",
}

SYSMON_MAPPING = {
    1:  [("TA0002", "T1059")],           # 프로세스 생성
    3:  [("TA0011", "T1071")],           # 네트워크 연결
    6:  [("TA0005", "T1562")],           # 드라이버 로드
    7:  [("TA0005", "T1055")],           # 이미지 로드
    8:  [("TA0004", "T1055")],           # 원격 스레드
    10: [("TA0006", "T1003")],           # lsass 접근
    11: [("TA0009", "T1005")],           # 파일 생성
    12: [("TA0003", "T1547")],           # 레지스트리
    13: [("TA0003", "T1547")],
    17: [("TA0008", "T1021")],           # 파이프
    19: [("TA0003", "T1546")],           # WMI
    20: [("TA0003", "T1546")],
    21: [("TA0003", "T1546")],
    22: [("TA0011", "T1071")],           # DNS
    23: [("TA0005", "T1070")],           # 파일 삭제
    25: [("TA0005", "T1055")],           # 프로세스 변조
}

SUSPICIOUS_PROCESS_MAPPING = {
    "mimikatz":   [("TA0006", "T1003")],
    "meterpreter":[("TA0011", "T1071"), ("TA0002", "T1059")],
    "psexec":     [("TA0008", "T1021")],
    "procdump":   [("TA0006", "T1003")],
    "powershell": [("TA0002", "T1059")],
    "cobalt":     [("TA0011", "T1071")],
    "empire":     [("TA0002", "T1059")],
}


# ─────────────────────────────────────────
#  추적기
# ─────────────────────────────────────────

class MitreTracker:
    def __init__(self, socketio):
        self.socketio = socketio
        self._lock = threading.Lock()
        # { (tactic_id, technique_id): count }
        self.hits = defaultdict(int)
        # 최근 이벤트 (최대 200건)
        self.recent = []
        self.total_mapped = 0

    # ------------------------------------------------------------------ #

    def map_threat(self, threat_type, src_ip=None, dst_ip=None, description="",
                   severity=None):
        mappings = THREAT_MAPPING.get(threat_type, [])
        sev = severity or self._threat_severity(threat_type)
        for tac, tech in mappings:
            self._record(tac, tech, f"{threat_type}: {description}",
                         src_ip, dst_ip, sev, source=threat_type)

    def map_sysmon_event(self, event_id, process=None, message="",
                         src_ip=None, dst_ip=None, severity=None):
        mappings = list(SYSMON_MAPPING.get(event_id, []))

        # 의심 프로세스 추가 매핑
        msg_l = (message or "").lower()
        proc_l = (process or "").lower()
        for keyword, extra_mapping in SUSPICIOUS_PROCESS_MAPPING.items():
            if keyword in msg_l or keyword in proc_l:
                mappings.extend(extra_mapping)

        sev = severity or "MEDIUM"
        for tac, tech in mappings:
            desc = f"Sysmon ID {event_id}" + (f" / {process}" if process else "")
            if message:
                desc += f" — {message[:120]}"
            self._record(tac, tech, desc, src_ip, dst_ip, sev,
                         source=f"sysmon:{event_id}", process=process)

    # ------------------------------------------------------------------ #

    @staticmethod
    def _threat_severity(threat_type):
        critical = {"METASPLOIT", "METERPRETER", "LSASS_DUMP", "MALWARE_BEACON",
                    "MALWARE_C2", "DATA_EXFIL"}
        high = {"DDOS", "PROC_INJECTION", "PS_ENCODED", "BRUTE_FORCE",
                "DNS_TUNNELING", "ARP_SPOOFING"}
        if threat_type in critical:
            return "CRITICAL"
        if threat_type in high:
            return "HIGH"
        return "MEDIUM"

    def _record(self, tactic_id, technique_id, description, src_ip, dst_ip,
                severity="MEDIUM", source=None, process=None):
        tech_info = next((t for t in TECHNIQUES.get(tactic_id, [])
                          if t["id"] == technique_id), None)
        tac_info  = next((t for t in TACTICS if t["id"] == tactic_id), None)

        with self._lock:
            key = (tactic_id, technique_id)
            self.hits[key] += 1
            self.total_mapped += 1
            entry = {
                "tactic_id":      tactic_id,
                "tactic_name":    tac_info["name"] if tac_info else tactic_id,
                "tactic_ko":      tac_info["ko"]   if tac_info else "",
                "technique_id":   technique_id,
                "technique_name": tech_info["name"] if tech_info else technique_id,
                "technique_ko":   tech_info["ko"]   if tech_info else "",
                "description":    description,
                "src_ip":         src_ip,
                "dst_ip":         dst_ip,
                "severity":       severity,
                "source":         source,
                "process":        process,
                "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.recent.append(entry)
            if len(self.recent) > 200:
                self.recent = self.recent[-200:]

        self.socketio.emit("mitre_hit", entry)

    # ------------------------------------------------------------------ #

    def get_matrix(self):
        """매트릭스 전체 구조 + 탐지 카운트 반환"""
        result = []
        for tac in TACTICS:
            techs = []
            for tech in TECHNIQUES.get(tac["id"], []):
                key = (tac["id"], tech["id"])
                techs.append({
                    **tech,
                    "count": self.hits.get(key, 0),
                })
            result.append({
                **tac,
                "techniques": techs,
                "total": sum(t["count"] for t in techs),
            })
        return {
            "tactics": result,
            "total_mapped": self.total_mapped,
            "unique_techniques": len([k for k, v in self.hits.items() if v > 0]),
        }

    def get_recent(self, limit=50):
        with self._lock:
            return list(reversed(self.recent))[:limit]

    def get_technique_detail(self, technique_id):
        """특정 Technique 상세: 메타데이터·최근 이벤트·연관 IP·방어권고"""
        tech_info = None
        tac_info = None
        for tac in TACTICS:
            for tech in TECHNIQUES.get(tac["id"], []):
                if tech["id"] == technique_id:
                    tech_info = tech
                    tac_info = tac
                    break
            if tech_info:
                break

        if not tech_info:
            return {
                "found": False,
                "technique_id": technique_id,
                "message": "해당 Technique을 찾을 수 없습니다.",
            }

        with self._lock:
            hits = [e for e in self.recent if e["technique_id"] == technique_id]
            total = self.hits.get((tac_info["id"], technique_id), 0)

        src_counter = defaultdict(int)
        dst_counter = defaultdict(int)
        proc_counter = defaultdict(int)
        sev_counter = defaultdict(int)
        for e in hits:
            if e.get("src_ip"):  src_counter[e["src_ip"]] += 1
            if e.get("dst_ip"):  dst_counter[e["dst_ip"]] += 1
            if e.get("process"): proc_counter[e["process"]] += 1
            sev_counter[e.get("severity", "MEDIUM")] += 1

        top_src = sorted(src_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dst = sorted(dst_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        top_proc = sorted(proc_counter.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "found":         True,
            "technique_id":  technique_id,
            "technique_name": tech_info["name"],
            "technique_ko":  tech_info["ko"],
            "tactic_id":     tac_info["id"],
            "tactic_name":   tac_info["name"],
            "tactic_ko":     tac_info["ko"],
            "description":   TECHNIQUE_DESCRIPTIONS.get(technique_id, ""),
            "total_count":   total,
            "severity_dist": dict(sev_counter),
            "recent":        list(reversed(hits))[:30],
            "top_src_ips":   [{"ip": ip, "count": c} for ip, c in top_src],
            "top_dst_ips":   [{"ip": ip, "count": c} for ip, c in top_dst],
            "top_processes": [{"name": n, "count": c} for n, c in top_proc],
            "defense":       DEFENSE_RECOMMENDATIONS.get(technique_id, []),
            "reference_url": f"https://attack.mitre.org/techniques/{technique_id}/",
        }

    def get_top_techniques(self, top=10):
        with self._lock:
            sorted_hits = sorted(self.hits.items(), key=lambda x: x[1], reverse=True)[:top]
        results = []
        for (tac, tech), count in sorted_hits:
            tech_info = next((t for t in TECHNIQUES.get(tac, []) if t["id"] == tech), None)
            tac_info  = next((t for t in TACTICS if t["id"] == tac), None)
            if tech_info and tac_info:
                results.append({
                    "tactic_id":    tac,
                    "tactic_name":  tac_info["name"],
                    "technique_id": tech,
                    "technique_name": tech_info["name"],
                    "ko":           tech_info["ko"],
                    "count":        count,
                })
        return results
