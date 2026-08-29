# 외부 시스템 연동 가이드

## VirusTotal

`VIRUSTOTAL_API_KEY`를 설정하면 SOAR의 `PB-MALWARE-ENRICH` 플레이북이
악성코드·EDR·Sigma 알림에서 MD5/SHA1/SHA256을 추출해 VirusTotal API v3의
기존 파일 리포트를 조회한다.

- `x-apikey` 헤더로 인증해 `GET /api/v3/files/{hash}`를 호출한다.
- 파일은 업로드하지 않으며 조회 결과는 기본 6시간 캐시한다.
- 네트워크/API 오류로 실행이 실패하면 대시보드의 `실패 단계 재시도` 버튼 또는
  `POST /api/soar/executions/{id}/retry`로 해시 조회부터 다시 실행할 수 있다.
- 완료 이력은 `data/soar_executions.db`에 저장되며 재시작 후 최근 100건을
  복원한다. 재시도 실행에는 원본 ID(`retry_of`)와 시도 횟수(`attempt`)가 남는다.
- 차단·트리아지처럼 부작용이 있는 플레이북은 중복 대응 방지를 위해 이 재시도
  API의 대상이 아니다.

### SOAR 차단 승인 게이트

기본 설정에서는 자동·수동 IP 차단이 즉시 실행되지 않고 `PB-BLOCK-APPROVAL`
실행으로 전환된다. AI 관제 센터의 승인 큐 또는 SOAR 상세 탭에서 승인·거절·
취소할 수 있으며, 승인한 로그인 사용자와 사유·시각은 실행 이력과 감사 로그에
남는다. 승인 요청은 기본 15분 후 만료된다.

```dotenv
SOAR_APPROVAL_REQUIRED=True
SOAR_APPROVAL_TIMEOUT_MINUTES=15
```

API에서는 `POST /api/soar/executions/{id}/approval`에
`{"decision":"approve|reject|cancel", "reason":"..."}`를 전송한다. 승인된
경우에만 방화벽 실행 경로로 진입하며 안전 목록 검사는 승인 요청 전에도 적용된다.

AI 관제 센터와 SOAR 상세 탭의 `대기 전체 승인`은 버튼을 누른 시점에 화면에
표시된 실행 ID만 최대 100건 승인한다. 확인 이후 새로 유입된 요청은 포함하지
않는다. API는 `POST /api/soar/approvals/batch`이며 요청 형식은
`{"execution_ids":[1,2], "reason":"..."}`이다.
- API 키 또는 해시가 없으면 단계가 `건너뜀`으로 표시되고 기존 트리아지는 계속된다.
- SOAR 실행 현황에서 대기·진행·완료·건너뜀·실패 상태를 실시간 확인한다.
- SOAR의 `EICAR 연결 테스트` 버튼은 안전한 테스트 해시로 인증·응답 파싱을 검증한다.
- 조회 결과는 알림 상세에 영속 저장되고 정탐 인시던트 승격 시 타임라인에도 기록된다.

---

현재 대시보드에는 다음 시스템의 빈 패널이 준비되어 있습니다.  
아래 가이드에 따라 실제 데이터를 연결할 수 있습니다.

---

## 방화벽 연동

### 지원 예정 시스템
- Palo Alto Networks (PAN-OS)
- Fortinet FortiGate
- Cisco ASA / Firepower
- pfSense / OPNsense

### 연동 방법 (Syslog)

```python
# modules/firewall_parser.py 생성 예시
import socket

class FirewallParser:
    def start_syslog_listener(self, port=514):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', port))
        # UDP Syslog 수신 루프
        while self.running:
            data, addr = sock.recvfrom(65535)
            self._parse_syslog(data.decode('utf-8', errors='ignore'))
```

### API 엔드포인트

```
POST /api/integrations/firewall
Content-Type: application/json

{
  "src_ip": "203.0.113.1",
  "dst_ip": "192.168.1.10",
  "dst_port": 443,
  "action": "DENY",
  "rule": "block-external-ssh",
  "timestamp": "2024-01-15T14:30:25Z"
}
```

---

## IPS/IDS 연동

### Snort fast-alert 연동

대시보드는 `/var/log/snort/snort.alert.fast`의 `-A fast` 출력을 tail하여 `SNORT_ALERT`로
정규화한다. Snort는 탐지만 담당하며 UFW를 직접 변경하지 않는다.

```dotenv
SNORT_ENABLED=True
SNORT_ALERT_PATH=/var/log/snort/snort.alert.fast
SNORT_INTERFACE=eth0
SNORT_HOME_NET=172.23.160.0/20
SOAR_MIN_BLOCK_CONFIDENCE=95
SOAR_REQUIRE_CORROBORATION=True
```

안전 기본값에서는 `CRITICAL`, 최종 판정 95% 이상, 독립 근거 2개 이상을 모두
만족해야 자동 차단 후보가 된다. 후보가 되어도 분석가 승인 게이트를 통과해야
UFW 명령이 실행된다. 데모 평판과 데모 이벤트는 차단 근거로 인정하지 않는다.

Snort와 UFW 설치는 현재 방화벽 상태를 백업하고 SSH(22), HTTP(80), Tailscale,
대시보드(5055)를 먼저 허용하는 스크립트로 수행한다.

```bash
sudo bash scripts/setup_snort_ufw_safe.sh
sudo bash scripts/repair_snort_single_interface.sh
sudo bash scripts/enable_ufw_safe.sh
sudo ufw status numbered
sudo snort -T -c /etc/snort/snort.conf -i eth0
```

설치 후 Snort의 `HOME_NET`을 실제 서버 대역(`172.23.160.0/20`)에 맞추고,
정상 관리·점검 IP는 `ipvar` 또는 suppress 목록으로 제외해야 오탐을 줄일 수 있다.
운영 서비스 포트와 Tailscale 관리 경로를 확인하기 전에는 기본 정책을 임의로
재작성하지 않는다.

대시보드의 **AI 관제 센터 → 탐지·방화벽 안전 상태**에서 Snort/UFW 요약을
확인하고, 사이드바의 **Snort · UFW** 탭에서 센서 구성, 수집 건수, 최근 SID와
출발지·목적지를 확인한다. `/api/integrations/snort`는 동일 정보를 JSON으로
제공한다. 화면은 현재 탭이 보일 때만 10초 간격으로 갱신한다.

SID별 표에는 분석가가 확정한 정탐·오탐 건수와 정탐률을 표시한다.
`SNORT_BLOCK_EXCLUDED_SIDS`에 등록된 SID는 탐지 이력에는 남지만 자동 차단의
독립 근거로 인정하지 않는다. 기본값 `254`는 Tailscale DNS 응답 오탐 억제용이다.

## 실운영 데이터와 분석가 판정

실전 센서 운영에서는 `.env`의 `DEMO_MODE=False`를 사용한다. 알림의 처리 상태
(`OPEN/ACK/CLOSED`)와 분석가 확정 판정은 별개이며, 판정은 다음 네 상태다.

- `UNREVIEWED`: 미판정
- `INVESTIGATING`: 조사 중
- `TRUE_POSITIVE`: 근거가 기록된 정탐 확정
- `FALSE_POSITIVE`: 근거가 기록된 오탐 확정

기존 데모 기간과 실운영의 경계는 다음 명령으로 무손실 아카이브한다. 실행 전
동일 DB의 시점 백업을 자동 생성하며 활성 행은 별도 `data/alerts_archive.db`로
이동한다. 활성 `alerts.db`와 장기 아카이브가 분리되어 실시간 조회 크기를 제한한다.

```bash
./venv/bin/python scripts/production_cutover.py
./venv/bin/python scripts/production_cutover.py --apply
```

인시던트 운영 저장소는 `data/incidents.db`다. 최초 실행 시 기존
`data/incidents.json`을 자동 이관하며 원본 JSON과 `.bak`은 삭제하지 않는다.

## 제한된 UFW SOAR helper

대시보드 사용자에게 일반 `ufw` sudo 권한을 주지 않는다. 아래 설치기는
`status`, 공개 IPv4 단건 `block/unblock`만 가능한 `/usr/local/sbin/soc-ufw`와
전용 sudoers 항목을 설치한다. helper도 사설·루프백·Tailscale·비 IPv4 입력을
거부한다.

```bash
sudo bash scripts/install_soar_ufw_helper.sh
sudo -n /usr/local/sbin/soc-ufw status
```

검증 후에만 `.env`를 `SOAR_BLOCK_MODE=ufw`로 변경한다. 복수 근거·95%·분석가
승인·TTL·allowlist 검사는 helper 호출 전에도 유지된다.

## 내부 자료 유출 SIEM·SOAR

`DATA_EXFIL`은 내부 호스트가 승인되지 않은 외부 목적지로 기본 5분 동안 500MB를
초과 전송할 때 생성한다. 목적지 IP 또는 접두는 `DATA_EXFIL_ALLOWLIST`로 제외할
수 있다. SIEM 상관 규칙은 다음 두 가지다.

- `R-INTERNAL-EXFIL`: 대량 외부 전송 또는 DNS 터널링
- `R-STAGING-EXFIL`: EDR/Sigma 수집·압축 징후 이후 같은 호스트의 외부 전송

`PB-DATA-EXFIL`은 알림 원문·호스트·목적지·전송량을 보존하고 영향 사용자·파일
범위를 조사할 인시던트를 만든다. 내부 호스트는 UFW로 자동 차단하지 않는다.
계정 비활성화, 세션 종료, 엔드포인트 격리는 분석가가 증거를 확인한 뒤 별도로
승인해야 한다.

### 지원 예정 시스템
- Suricata
- Zeek (Bro)

### Suricata EVE JSON 파싱

```python
# Suricata의 eve.json 파일 tail
import json, time

def tail_eve_json(path="/var/log/suricata/eve.json"):
    with open(path, 'r') as f:
        f.seek(0, 2)  # 파일 끝으로
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            event = json.loads(line)
            if event.get('event_type') == 'alert':
                yield event
```

---

## 백신 서버 연동

> **먼저: 로컬 탐지가 이미 있다.** 외부 백신 서버 연동은 *추가* 선택지이지
> 전제 조건이 아니다.
>
> | 방식 | 무엇을 잡나 | 한계 |
> |------|-------------|------|
> | `hash_checker` | 알려진 악성 해시와 정확히 일치하는 파일 | 한 바이트만 바뀌어도 놓친다 |
> | `yara_scanner` | 파일 **내용의 패턴** — 웹셸·리버스셸·마이너·드로퍼 | 룰이 없는 유형은 못 잡는다 |
>
> YARA 는 EDR 이 관측한 실행 파일과 `YARA_WATCH_DIRS` 의 새 파일을 자동 검사하고,
> 매치 시 `MALWARE_FILE` 알림으로 기존 트리아지 파이프라인에 들어간다.
> 자세한 건 [detection_rules.md](detection_rules.md) 참조.
>
> 아래 외부 백신 연동은 **엔터프라이즈 환경에서 기존 백신의 탐지 이벤트를 함께
> 수집하고 싶을 때**의 참고 예시다(미구현).

### AhnLab V3 (API 예시)

```python
import requests

class AntivirusConnector:
    def __init__(self, server_url, api_key):
        self.base = server_url
        self.headers = {"X-API-Key": api_key}

    def get_detections(self, since=None):
        r = requests.get(
            f"{self.base}/api/v1/detections",
            headers=self.headers,
            params={"since": since}
        )
        return r.json()
```

---

## EDR 연동

### CrowdStrike Falcon API

```python
from falconpy import EventStreams

class EDRConnector:
    def stream_events(self, api_key, api_secret):
        falcon = EventStreams(
            client_id=api_key,
            client_secret=api_secret
        )
        # 실시간 탐지 이벤트 스트리밍
```

---

## SIEM 연동

### Elastic SIEM

```python
from elasticsearch import Elasticsearch

class SIEMConnector:
    def __init__(self, hosts):
        self.es = Elasticsearch(hosts)

    def query_alerts(self, index="siem-signals-*"):
        return self.es.search(
            index=index,
            body={"query": {"match_all": {}}, "size": 100}
        )
```

### Splunk REST API

```bash
curl -k -u admin:password \
  https://splunk-server:8089/services/search/jobs \
  -d "search=search index=security earliest=-1h"
```

---

## 연동 패널 활성화 방법

1. `modules/` 에 파서 모듈 생성 (`start()`, `stop()`, `get_events()` 구현)
2. `app.py` 에 서비스 등록:
   ```python
   from modules.firewall_parser import FirewallParser
   app.firewall = FirewallParser(socketio)
   app.firewall.start()
   ```
3. `api/routes.py` 에 엔드포인트 추가
4. `templates/dashboard.html` 의 빈 패널 교체:
   - `panel-firewall` 안의 `.empty-panel` 을 실제 테이블로 교체
5. `static/js/dashboard.js` 에 SocketIO 이벤트 핸들러 추가
