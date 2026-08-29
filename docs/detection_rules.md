# 위협 탐지 규칙

## 현재 구현된 탐지 규칙

### 네트워크 기반 탐지

| 규칙 ID | 이름 | 조건 | 심각도 | 임계값 변경 |
|---------|------|------|--------|------------|
| NET-001 | DDoS SYN Flood | 평균 **2,000+ pps 가 3초 지속** | CRITICAL | `DDOS_PACKET_THRESHOLD` |
| NET-002 | 포트 스캔 | 동일 IP 30초 내 **40+ 고유 포트** | HIGH | `PORT_SCAN_THRESHOLD` |
| NET-003 | 내부 자료 대량 유출 | 내부 IP가 비허용 외부 목적지로 기본 5분 내 500MB+ 전송 | HIGH/CRITICAL | `DATA_EXFIL_*` 설정 및 allowlist 지원 |
| NET-004 | ARP 스푸핑 | 게이트웨이 MAC 위장 | MEDIUM | - |
| NET-005 | DNS 터널링 | 비정상 DNS 쿼리 길이/빈도 | MEDIUM | - |

### 호스트 기반 탐지 (Sysmon)

| 이벤트 ID | 탐지 내용 | 심각도 |
|-----------|-----------|--------|
| 의심 프로세스 | mimikatz, meterpreter, cobalt strike 등 | CRITICAL/HIGH |
| 의심 경로 실행 | %TEMP%, %APPDATA%, Public 폴더에서 실행 | HIGH |
| lsass 접근 | Event ID 10 + lsass.exe 대상 | CRITICAL |
| WMI 지속성 | Event ID 19/20/21 | HIGH |
| 프로세스 변조 | Event ID 25 | CRITICAL |
| 원격 스레드 생성 | Event ID 8 | HIGH |
| 드라이버 로드 | Event ID 6 (미서명) | HIGH |

### 파일/해시 기반 탐지

| 규칙 | 조건 | 심각도 |
|------|------|--------|
| 악성 해시 MD5 | `data/malicious_hashes.txt` DB 매칭 | CRITICAL |
| 악성 해시 SHA256 | `data/malicious_hashes.txt` DB 매칭 | CRITICAL |

**해시 대조는 '알려진 바로 그 파일'만 잡는다** — 한 바이트만 바뀌어도 놓친다.
그 빈틈은 아래 YARA 가 메운다. 둘은 대체가 아니라 보완이다.

### 파일 내용 기반 탐지 (YARA)

`data/yara/*.yar`. 매치 시 `MALWARE_FILE` 알림으로 AI 트리아지 파이프라인에 들어간다.

| 룰 | 심각도 | MITRE | 범위 |
|----|--------|-------|------|
| `SOC_PHP_Webshell` | CRITICAL | T1505 | auto |
| `SOC_Reverse_Shell_Script` | CRITICAL | T1059 | auto |
| `SOC_Cryptominer_Artifact` | HIGH | T1496 | auto |
| `SOC_Curl_Pipe_Shell_Dropper` | HIGH | T1105 | auto |
| `SOC_EICAR_Test_File` | LOW | T1204 | auto (배선 검증용) |
| `SOC_UPX_Packed_ELF` | MEDIUM | T1027 | **manual** |

**`meta.scope`** — `auto` 는 자동 스캔에도 쓰고 `manual` 은 분석가가 경로를 지목한
수동 스캔에서만 쓴다. UPX 패킹이 manual 인 이유: **패킹 자체는 악성이 아니다.**
정상 소프트웨어도 쓰고, 패커 도구(`/usr/bin/upx-ucl`)가 자기 시그니처를 담고 있다.
패킹은 탐지가 아니라 정황이라, 시스템 전체를 훑을 때는 소음이고 특정 파일을
들여다볼 때는 의미가 있다.

**스캔 경로 세 갈래**
1. 수동 — `/api/yara/scan` (경로는 `HASH_SCAN_ALLOWED_DIRS` 로 제한)
2. 자동 ① — EDR 이 관측한 프로세스의 **실행 파일**. Sigma 가 '무엇을 실행했나'를
   본다면 여기는 '그 파일이 무엇인가'를 본다 — 이름을 바꿔 위장한 바이너리는
   커맨드라인만으로는 안 잡힌다.
3. 자동 ② — `YARA_WATCH_DIRS` 에 새 파일이 생기면 검사

같은 파일은 (경로+크기+mtime) 지문 캐시로 한 번만 읽는다. 심볼릭 링크는 따라가지
않고(경로 탈출 방지), 매치 결과에 원문 페이로드를 담지 않는다(패턴 식별자와 개수만).

---

## detection-as-code — 룰도 코드다

**룰을 고치면 테스트가 돌아야 한다.** 그러지 않으면 룰 수정은 언제나 도박이다.
Sigma·YARA 룰은 각각 **정탐/오탐 샘플을 함께 들고 다니고**, CI 의 전용 단계
(`탐지 룰 검증`)가 매 push 마다 검증한다.

| | 테스트 위치 | 이유 |
|---|---|---|
| Sigma | 룰 `.yml` 안 `tests:` 블록 | 엔진은 `detection` 만 읽으므로 무시된다 |
| YARA | `data/yara/rule_tests.yml` | YARA `meta` 는 스칼라만 담아 룰 안에 못 넣는다 |

**negative 가 핵심이다.** 오탐은 조용히 쌓이다가 분석가가 알림을 무시하게 만드는
방식으로 탐지 체계를 망가뜨린다. 테스트 없는 룰은 CI 가 막는다.

실제로 이 검증이 오탐을 여러 건 잡았다:

- **Sigma 크립토마이너** — CommandLine 에 `pool` 만 있어도 매치해서
  `gunicorn --worker-pool=gevent` 와 `java -Dpool.maxSize=20` 같은 **정상 프로세스를
  HIGH 로** 올리고 있었다. 채굴 풀을 특정하는 문자열만 남겼다.
- **YARA 드로퍼** — `curl `과 `| sh` 를 각각 찾아 AND 로 묶었더니 `/usr/bin` 743개
  중 `ctest`·`tailscale` 이 걸렸다(문자열이 서로 멀리 떨어져 있었을 뿐). 근접성
  조건으로 바꿨고, 그래도 GNU `parallel` 이 자기 설치 안내문 때문에 걸려
  **스킴 있는 전체 URL**을 요구하도록 다시 조였다.

`test_system_files_do_not_false_positive` 가 `/usr/bin`·`/usr/sbin`·`/bin` 을 실제로
스캔한다. **이 테스트가 실패하면 진짜 오탐을 찾은 것이다** — 그냥 넘기지 말 것.

---

## 커버리지 자가 진단 — 무엇을 *못* 잡는가

히트 0 인 기법이 '공격이 없었다'인지 '룰이 없어 못 본다'인지 구분되지 않으면
매트릭스는 절반만 말하는 것이다. `/api/mitre/coverage` 가 세 축을 조인해 그 구분을
만든다 — (A) 룰이 있는가 · (B) 퍼플팀이 검증했는가 · (C) 실제 히트가 있었는가.

**공백 목록이 곧 다음에 써야 할 룰의 목록이다.** 실측(2026-08-29): 기법 41개 중
룰 보유 24개(58.5%) · 공백 17개.

---

## 탐지 규칙 추가 방법

### 새 네트워크 탐지 규칙

`modules/threat_detector.py` 의 `analyze_packet()` 메서드에 추가:

```python
def analyze_packet(self, src_ip, dst_ip, dst_port, proto, length):
    # 기존 코드...

    # 새 규칙 예시: 의심 포트 접근
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337}
    if dst_port in SUSPICIOUS_PORTS:
        self._add_alert(Alert(
            "MALWARE_BEACON", "HIGH", src_ip, dst_ip,
            f"의심 포트 접근: {dst_port} (C2 포트)",
            {"port": dst_port},
        ))
```

### 새 악성 해시 추가

`data/malicious_hashes.txt` 에 한 줄 추가:
```
sha256,<SHA256_해시>,<악성코드_이름>
```

### 탐지 임계값 조정

`.env` 파일에서 조정:
```env
DDOS_PACKET_THRESHOLD=500    # 더 민감하게 (기본: 1000)
PORT_SCAN_THRESHOLD=10       # 더 민감하게 (기본: 20)
```

---

## 오탐(False Positive) 관리

1. **분석가 확정 판정**: `TRUE_POSITIVE` / `FALSE_POSITIVE` 를 근거와 함께 기록한다
   (`/api/alerts/<id>/verdict`). 이 판정이 SID별 품질 통계와 ML 피드백의 재료다.
2. **AI 트리아지**: CRITICAL/HIGH 는 서버 SOAR 가 1회 자동 판정한다.
3. **중복제거·억제**(`alert_dedup`): 같은 핑거프린트를 병합하고 운영자 규칙으로
   억제한다. **억제된 것도 원문째 보관**되어 `/api/dedup/suppressed` 로 복구된다 —
   조용히 사라지는 알림은 없다. 실측 11만 건 리플레이에서 31.2% 감축.
4. **차단 제외**: `SOAR_BLOCK_ALLOWLIST`(사설·CGNAT·Tailscale·자기 자신은 자동 보호),
   `SNORT_BLOCK_EXCLUDED_SIDS`(표시는 하되 자동 차단 근거에서 제외).
5. **룰 자체를 고친다**: 오탐 샘플을 룰 테스트의 negative 에 넣고 조건을 좁힌다.
   위 detection-as-code 절 참조 — 이게 근본 해결이고 나머지는 완화다.

---

## MITRE ATT&CK 매핑

| 탐지 규칙 | ATT&CK Technique |
|-----------|-----------------|
| DDoS | T1498 - Network Denial of Service |
| 포트 스캔 | T1046 - Network Service Discovery |
| Mimikatz | T1003 - OS Credential Dumping |
| lsass 접근 | T1003.001 - LSASS Memory |
| ARP 스푸핑 | T1557.002 - ARP Cache Poisoning |
| DNS 터널링 | T1071.004 - DNS C2 |
| WMI 지속성 | T1546.003 - WMI Event Subscription |
| 데이터 유출 | T1048 - Exfiltration Over Alternative Protocol |
| YARA 웹셸 | T1505 - Server Software Component |
| YARA 리버스셸 | T1059 - Command and Scripting Interpreter |
| YARA 크립토마이너 | T1496 - Resource Hijacking |
| YARA 드로퍼 | T1105 - Ingress Tool Transfer |
| YARA UPX 패킹 | T1027 - Obfuscated Files or Information |

> 룰이 가리키는 기법은 **매트릭스에 칸이 있어야 한다** — 없으면 탐지돼도 표시될
> 곳이 없다. 커버리지 진단이 실제로 그 상태를 찾아냈고(T1496·T1505), 테스트가
> 재발을 막는다.
