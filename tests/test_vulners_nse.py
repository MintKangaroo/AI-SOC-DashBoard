"""nmap vulners 연동 — 내장 스크립트 해석 + 결과 파서(스키마 2.0 구조화 + 구형 폴백)."""
import os
import xml.etree.ElementTree as ET

import pytest

from modules.vuln_scanner import VulnScanner

XML_V2 = """<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.17"/>
<script id="vulners" output="cpe:/a:openbsd:openssh:8.9p1  4 findings">
<elem key="schema">2.0</elem>
<table key="cpe:/a:openbsd:openssh:8.9p1">
<table><elem key="id">PACKETSTORM:179290</elem><elem key="type">packetstorm</elem><elem key="cvss">10.0</elem><elem key="is_exploit">true</elem></table>
<table><elem key="id">CVE-2023-38408</elem><elem key="type">cve</elem><elem key="cvss">9.8</elem><elem key="is_exploit">false</elem></table>
<table><elem key="id">CVE-2024-6387</elem><elem key="type">cve</elem><elem key="cvss">8.1</elem><elem key="exploit_known">true</elem></table>
<table><elem key="id">CVE-2023-38408</elem><elem key="type">cve</elem><elem key="cvss">7.0</elem></table>
<table><elem key="id">CVE-2020-9999</elem><elem key="type">cve</elem><elem key="cvss">77</elem></table>
</table></script></port>"""

XML_OLD = """<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/>
<script id="vulners" output="cpe:/a:openbsd:openssh:8.9p1:&#xa;\tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408&#xa;\tEXPLOITPACK:1\t9.8\thttps://vulners.com/x\t*EXPLOIT*"/></port>"""


def _script(xml):
    return ET.fromstring(xml).find("script")


def test_structured_schema_yields_cves_only_and_marks_exploits():
    cves = VulnScanner._parse_vulners_script(_script(XML_V2))
    ids = {c["cve"]: c for c in cves}
    assert set(ids) == {"CVE-2023-38408", "CVE-2024-6387"}, "익스플로잇 자료·이상값은 CVE 가 아니다"
    assert ids["CVE-2023-38408"]["cvss"] == 9.8 and ids["CVE-2023-38408"]["severity"] == "critical"
    assert ids["CVE-2024-6387"]["exploit_known"] is True and "공개 익스플로잇" in ids["CVE-2024-6387"]["desc"]
    assert any("익스플로잇 자료 1건" in c["desc"] for c in cves)


def test_legacy_output_still_parses():
    cves = VulnScanner._parse_vulners_script(_script(XML_OLD))
    assert [c["cve"] for c in cves] == ["CVE-2023-38408"] and cves[0]["cvss"] == 9.8


def test_bundled_script_is_used_when_system_copy_absent(monkeypatch):
    assert os.path.exists(VulnScanner._BUNDLED_VULNERS), "data/nse/vulners.nse 가 없다"
    monkeypatch.setattr(VulnScanner, "_SYSTEM_VULNERS", "/nonexistent/vulners.nse")
    assert VulnScanner.vulners_script() == VulnScanner._BUNDLED_VULNERS
    monkeypatch.setattr(VulnScanner, "_BUNDLED_VULNERS", "/nonexistent/b.nse")
    assert VulnScanner.vulners_script() is None


def test_bundled_script_is_the_vulners_nse():
    src = open(VulnScanner._BUNDLED_VULNERS, encoding="utf-8", errors="replace").read()
    assert "vulners.com" in src and "portrule" in src and "categories" in src


@pytest.mark.skipif(not os.path.exists("/usr/bin/nmap"), reason="nmap 없음")
def test_nmap_accepts_bundled_script_path():
    """nmap 이 경로 지정 스크립트를 로드하는지만 본다(네트워크 질의 없이 --script-help)."""
    import subprocess
    r = subprocess.run(["nmap", "--script-help", VulnScanner._BUNDLED_VULNERS],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "vulners" in r.stdout.lower(), r.stderr[-300:]
