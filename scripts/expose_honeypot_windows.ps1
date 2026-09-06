# 허니팟 공개 노출 — Windows 쪽 절반. 관리자 PowerShell 에서 실행.
#
# WSL2 는 NAT 뒤라 Windows 가 받은 연결을 WSL IP 로 넘겨야 한다(portproxy).
# WSL IP 는 재부팅마다 바뀔 수 있으므로 이 스크립트는 매번 현재 IP 를 읽어 규칙을 갱신한다.
# 대시보드 포트 5055 는 절대 포함하지 않는다 — 대시보드는 Tailscale 로만 접근한다.
#
# 실행 후 공유기에서 같은 포트를 이 PC 로 포트포워딩해야 인터넷에서 닿는다.
# 되돌리기: .\expose_honeypot_windows.ps1 -Remove
param([switch]$Remove)
$ErrorActionPreference = "Stop"
$ports = @(2222, 2323, 3306, 6379, 9200, 8082)   # .env HONEYPOT_PORTS 와 같아야 한다
if ($ports -contains 5055) { throw "5055 는 대시보드 포트다 — 노출 금지" }

$wslIp = (wsl hostname -I).Trim().Split(" ")[0]
if (-not $wslIp) { throw "WSL IP 를 읽지 못했다 — WSL 이 떠 있는지 확인" }
Write-Host "WSL IP: $wslIp"

foreach ($p in $ports) {
    netsh interface portproxy delete v4tov4 listenport=$p listenaddress=0.0.0.0 2>$null | Out-Null
    Remove-NetFirewallRule -DisplayName "SOC honeypot $p" -ErrorAction SilentlyContinue
    if (-not $Remove) {
        netsh interface portproxy add v4tov4 listenport=$p listenaddress=0.0.0.0 connectport=$p connectaddress=$wslIp | Out-Null
        New-NetFirewallRule -DisplayName "SOC honeypot $p" -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow | Out-Null
        Write-Host "  $p → ${wslIp}:$p 허용"
    } else { Write-Host "  $p 제거" }
}
netsh interface portproxy show v4tov4
if (-not $Remove) {
    Write-Host "`n다음: 공유기 포트포워딩 → 이 PC($((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notmatch 'WSL|Loopback|vEthernet'} | Select-Object -First 1).IPAddress)) 로 $($ports -join ', ')"
    Write-Host "WSL 재부팅 후 IP 가 바뀌면 이 스크립트를 다시 실행."
}
