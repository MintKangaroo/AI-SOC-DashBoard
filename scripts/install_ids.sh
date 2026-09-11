#!/usr/bin/env bash
# Suricata + Zeek 설치·설정 (Ubuntu 22.04 / WSL2). 대시보드 수집기는 파일이 생기면 자동으로 붙는다.
#   sudo bash scripts/install_ids.sh [인터페이스=eth0] [대시보드 사용자=$SUDO_USER]
# - Suricata: apt 패키지(6.0.x) + ET Open 룰셋, af-packet 으로 인터페이스 감시, eve.json → /var/log/suricata/eve.json
# - Zeek: OBS 공식 저장소(zeek-lts), notice.log 를 JSON 으로, /opt/zeek/logs/current/notice.log
# 메모리: 둘을 합쳐 약 1GB 가 더 든다. WSL 가용 메모리(free -g)를 먼저 볼 것.
set -euo pipefail
IFACE="${1:-eth0}"
DASH_USER="${2:-${SUDO_USER:-$USER}}"
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요"; exit 1; }
ip link show "$IFACE" >/dev/null 2>&1 || { echo "인터페이스 $IFACE 없음"; ip -br link; exit 1; }
export DEBIAN_FRONTEND=noninteractive

echo "== [1/4] Suricata"
apt-get update -qq
apt-get install -y -qq suricata jq >/dev/null
# 감시 인터페이스 (af-packet 첫 항목) 와 HOME_NET(사설망 기본값 유지)
sed -i -E "0,/^  - interface: .*/s//  - interface: ${IFACE}/" /etc/suricata/suricata.yaml
# 룰셋(ET Open). 네트워크가 막혀 있으면 기본 룰만으로 동작
suricata-update -q || echo "  (suricata-update 실패 — 기본 룰만 사용)"
systemctl enable --now suricata
usermod -aG suricata "$DASH_USER"
# eve.json 은 suricata 그룹 640 — 대시보드 사용자가 읽을 수 있게
chmod 750 /var/log/suricata 2>/dev/null || true

echo "== [2/4] Zeek (OBS security:zeek 저장소)"
. /etc/os-release
REPO="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}/"
curl -fsSL "${REPO}Release.key" | gpg --dearmor -o /usr/share/keyrings/security_zeek.gpg
echo "deb [signed-by=/usr/share/keyrings/security_zeek.gpg] ${REPO} /" > /etc/apt/sources.list.d/security:zeek.list
apt-get update -qq
apt-get install -y -qq zeek-lts >/dev/null
Z=/opt/zeek
sed -i -E "s/^interface=.*/interface=${IFACE}/" $Z/etc/node.cfg
grep -q 'json-logs' $Z/share/zeek/site/local.zeek || echo '@load policy/tuning/json-logs.zeek' >> $Z/share/zeek/site/local.zeek
# WSL 은 timezone/hostname 이 zeekctl 검사에 걸릴 수 있어 SendMail 을 끈다
sed -i -E 's/^#?SendMail *=.*/SendMail = /' $Z/etc/zeekctl.cfg
$Z/bin/zeekctl deploy
# 로그 회전(시간별)은 zeekctl cron 이 한다
( crontab -l 2>/dev/null | grep -v 'zeekctl cron'; echo "*/5 * * * * $Z/bin/zeekctl cron" ) | crontab -
chmod -R o+rX $Z/logs
# zeek 가 부팅 시 자동 시작되도록 (WSL 재시작 뒤)
cat > /etc/systemd/system/zeek.service <<UNIT
[Unit]
Description=Zeek network monitor (zeekctl)
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$Z/bin/zeekctl start
ExecStop=$Z/bin/zeekctl stop
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable zeek >/dev/null

echo "== [3/4] 상태"
systemctl is-active suricata && ls -la /var/log/suricata/eve.json
$Z/bin/zeekctl status
ls -la $Z/logs/current/ | head -5

echo "== [4/4] 다음"
echo " - 대시보드 사용자($DASH_USER)가 suricata 그룹 반영을 받으려면 대시보드 서비스 재기동:"
echo "     systemctl --user restart soc-dashboard   (일반 사용자로)"
echo " - 모듈 헬스에서 'Suricata IDS'·'Zeek' 가 real 로 바뀌면 끝. notice.log 는 Zeek 가 notice 를 낼 때 생긴다."
