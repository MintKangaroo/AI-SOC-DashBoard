# data/nse — nmap NSE 스크립트 사본

`vulners.nse` — https://github.com/vulnersCom/nmap-vulners (MIT).
nmap 7.80(Ubuntu 22.04)은 이 스크립트를 탑재하지 않고, `/usr/share/nmap/scripts/` 에
넣으려면 sudo 가 필요하다. nmap 은 `--script <파일경로>` 도 받으므로 여기 두고
`VulnScanner.vulners_script()` 가 시스템 설치본 → 이 사본 순으로 고른다.

- 스크립트는 vulners.com API 에 질의한다 — 인터넷이 필요하고, 격리망에서는 CVE 없이
  서비스 식별만 된다.
- 키는 선택(`VULNERS_API_KEY`). 없어도 CVE·CVSS 는 나온다.
- 갱신: `curl -sfL -o data/nse/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse`
  후 `tests/test_vulners_nse.py` 통과 확인(출력 스키마가 바뀌면 파서가 먼저 알아야 한다).
