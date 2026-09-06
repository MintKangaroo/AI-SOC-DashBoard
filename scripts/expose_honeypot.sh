#!/usr/bin/env bash
# 허니팟 공개 노출 — WSL 쪽 절반. (Windows 쪽 절반은 scripts/expose_honeypot_windows.ps1)
#
# 무엇을 하나:
#   1. .env 의 HONEYPOT_BIND 를 0.0.0.0 으로 (현재 Tailscale IP 에만 바인드 → 공개 접촉 0건)
#   2. ufw 에 허니팟 포트만 inbound 허용 (대시보드 5055 는 절대 열지 않는다)
#   3. 대시보드 재기동 안내
#
# 왜 이 순서인가: 바인드만 바꾸면 ufw 가 막고, ufw 만 열면 리스너가 Tailscale IP 에만 있다.
# 선행조건(감사 B-5)은 해소돼 있다 — HONEYPOT_MAX_CONNS(기본 200) 초과 접속은 접촉만
# 기록하고 즉시 끊으므로 스레드 고갈로 죽지 않는다.
#
# WSL2 는 NAT 뒤다. 이 스크립트가 끝나도 인터넷에서 닿으려면
#   (a) Windows 에서 portproxy + 방화벽 인바운드   → expose_honeypot_windows.ps1
#   (b) 공유기에서 같은 포트를 Windows PC 로 포트포워딩
# 이 두 단계가 더 필요하다. 둘 다 이 저장소 밖의 결정이라 스크립트가 대신하지 않는다.
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "sudo 로 실행하세요: sudo bash scripts/expose_honeypot.sh"; exit 1; fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$repo_dir/.env"
[[ -f "$env_file" ]] || { echo ".env 가 없습니다: $env_file"; exit 1; }

ports="$(grep -E '^HONEYPOT_PORTS=' "$env_file" | cut -d= -f2 | cut -d'#' -f1 | tr -d ' ')"
[[ -n "$ports" ]] || { echo ".env 에 HONEYPOT_PORTS 가 없습니다"; exit 1; }
if echo ",$ports," | grep -q ",5055,"; then echo "HONEYPOT_PORTS 에 대시보드 포트 5055 가 있습니다 — 중단"; exit 1; fi

echo "[1/3] HONEYPOT_BIND → 0.0.0.0"
cp "$env_file" "$env_file.bak-$(date +%F-%H%M%S)"
if grep -qE '^HONEYPOT_BIND=' "$env_file"; then
  sed -i -E 's/^HONEYPOT_BIND=.*/HONEYPOT_BIND=0.0.0.0   # 공개 노출 (expose_honeypot.sh)/' "$env_file"
else
  echo 'HONEYPOT_BIND=0.0.0.0   # 공개 노출 (expose_honeypot.sh)' >> "$env_file"
fi

echo "[2/3] ufw: 허니팟 포트만 허용 ($ports)"
ufw status numbered > "$repo_dir/logs/ufw-before-honeypot-$(date +%F-%H%M%S).txt" 2>&1 || true
IFS=',' read -ra arr <<< "$ports"
for p in "${arr[@]}"; do
  [[ "$p" =~ ^[0-9]+$ ]] || continue
  ufw allow "$p"/tcp comment "honeypot decoy $p"
done
ufw status | grep -E "^(Status|5055)" || true
if ufw status | grep -qE '^5055'; then echo "⚠ 5055 가 ufw 에 열려 있습니다 — 대시보드는 Tailscale 로만 접근해야 합니다. 확인하세요."; fi

echo "[3/3] 대시보드를 재기동해야 새 바인드가 적용됩니다:"
echo "    kill \$(cat logs/dashboard.pid) && setsid ./venv/bin/python app.py > logs/dashboard.out 2>&1 < /dev/null &"
echo "확인: ss -ltnp | grep -E ':(${ports//,/|}) '  →  0.0.0.0 으로 LISTEN 이어야 합니다"
echo "다음: Windows PowerShell(관리자)에서 scripts/expose_honeypot_windows.ps1, 그리고 공유기 포트포워딩"
