#!/usr/bin/env bash
# 실트래픽 캡처 권한 부여 — ML 실트래픽 피처 수집의 전제.
#
# 왜 필요한가:
#   PyShark·Scapy 가 없거나 캡처 권한이 없으면 PacketAnalyzer 는 DEMO_MODE=False
#   로도 합성 루프로 돈다(그때 ML 피처는 origin='demo' 로 기록된다 — 합성이
#   실트래픽으로 둔갑하지 않게 하는 안전장치다). 즉 권한 없이는 몇 시간을
#   가동해도 실트래픽 피처가 0건에서 늘지 않는다.
#
# 왜 dumpcap 인가:
#   venv 의 python 인터프리터에 직접 cap_net_raw 를 주면 **그 인터프리터로
#   실행되는 모든 코드**가 원시 소켓을 얻는다(=이 저장소의 모든 스크립트).
#   dumpcap 은 캡처만 하는 작은 전용 바이너리라 권한 범위가 훨씬 좁다.
#   그래서 PyShark(→dumpcap) 경로를 기본으로 한다.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "sudo로 실행하세요: sudo bash scripts/enable_packet_capture.sh"; exit 1
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
user_name="${SUDO_USER:-mintkangaroo}"

echo "[1/4] tshark(dumpcap) 설치"
export DEBIAN_FRONTEND=noninteractive
# 설치 중 "비루트 캡처 허용" 대화상자를 묻지 않고 예로 답한다
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
apt-get update -qq
apt-get install -y -qq tshark >/dev/null

dumpcap_path="$(command -v dumpcap)"
echo "     dumpcap: ${dumpcap_path}"

echo "[2/4] dumpcap 에 캡처 권한 부여(cap_net_raw, cap_net_admin)"
setcap cap_net_raw,cap_net_admin+eip "${dumpcap_path}"
getcap "${dumpcap_path}"

echo "[3/4] ${user_name} 을 wireshark 그룹에 추가"
groupadd -f wireshark
chgrp wireshark "${dumpcap_path}"
chmod 0750 "${dumpcap_path}"
usermod -aG wireshark "${user_name}"

echo "[4/4] pyshark 설치(venv)"
runuser -u "${user_name}" -- "${repo_dir}/venv/bin/pip" install -q pyshark==0.6

cat <<'MSG'

완료. 다음이 남았습니다:

  1) 그룹 반영을 위해 **로그아웃 후 재로그인**(또는 WSL 재시작: wsl --shutdown).
     그 전까지는 여전히 권한 오류가 납니다.

  2) 확인:
       ./venv/bin/python scripts/eval_ml.py | grep '수집 전제'
     "OK — PyShark 사용 가능" 이 나와야 합니다.

  3) 그 다음 서버를 실모드로 가동하면 실트래픽 피처가 쌓입니다.
     피처가 정말 real 로 기록되는지 반드시 확인하세요:
       sqlite3 data/ml_features.db \
         "SELECT origin, COUNT(*) FROM features GROUP BY origin;"
     demo 로 찍히면 캡처가 아직 폴백 중이라는 뜻입니다.

주의 — 여기는 WSL2 입니다:
  eth0 는 WSL VM 의 가상 NIC 라서 **이 VM 이 주고받는 트래픽만** 보입니다.
  Windows 호스트나 같은 LAN 의 다른 장비 트래픽은 보이지 않습니다.
  즉 여기서 모이는 '실트래픽' 은 이 머신 자신의 통신이며, 그것으로 학습한
  이상탐지 모델의 적용 범위도 딱 거기까지입니다. 게이트웨이 미러링 없이
  '네트워크 전체를 관제한다' 고 주장하지 마세요.
MSG
