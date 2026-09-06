# SOC 대시보드 — 데모 모드로 어디서나 뜨는 이미지.
#
# 실제 센서(패킷 캡처·Sysmon·nmap·Ansible)는 이미지에 넣지 않는다. 모든 모듈이
# 데모 fallback 을 갖고 있어 없어도 전체 화면이 동작하고, 그 fallback 이 진짜인지가
# 이 이미지가 검증하는 것이다(실서버 테스트가 "빈 디렉터리에서 기동" 을 보는 것과
# 같은 이유). 실캡처가 필요하면 호스트 네트워크 + NET_RAW/NET_ADMIN 으로 띄우고
# tshark 를 얹은 파생 이미지를 만든다.
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DEMO_MODE=True HOST=0.0.0.0 PORT=5055 \
    SOAR_BLOCK_MODE=simulate SOAR_AUTO_BLOCK=False PATCH_APPLY_ENABLED=False

# libpcap: scapy 가 import 시 찾는다(없어도 데모 fallback 이지만 경고가 시끄럽다)
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# 테스트 전용 의존성(playwright·py-ocsf-models)은 런타임 이미지에서 뺀다
RUN grep -vE '^(playwright|py-ocsf-models)==' requirements.txt > /tmp/req.txt \
    && pip install --no-cache-dir -r /tmp/req.txt

COPY . .
# 알림·감사·피처 DB 는 볼륨으로 — 이미지에 데이터가 박히면 안 된다
RUN mkdir -p data logs && useradd -r -u 10001 soc && chown -R soc:soc /app
USER soc
VOLUME ["/app/data", "/app/logs"]
EXPOSE 5055

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5055/login', timeout=4).status==200 else 1)"

CMD ["python", "app.py"]
