"""TOP 공격자 집계 상한·스로틀 (docs/AUDIT.md E-3).

`_attackerCounter` 는 고유 공격 IP 마다 항목이 늘고 **정리되지 않았다.** 관제
화면은 며칠씩 켜두는 물건이라 이건 진짜 누수다. 게다가 `renderTopAttackers()`
가 매 알림마다 전체를 sort() 해서 O(n log n) × 알림 수였다.

JS 테스트 인프라가 없으므로, 실제 배포되는 `02-overview.js` 에서 집계 로직
구간을 잘라내 node 로 실행한다 — 코드를 복사해두고 검증하는 게 아니라 파일
자체를 읽는다. node 가 없으면 건너뛴다(순수 정적 검사는 그대로 돈다).
"""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
OVERVIEW = REPO / "static" / "js" / "dash" / "02-overview.js"
RESPONSE_INIT = REPO / "static" / "js" / "dash" / "08-response-init.js"

_START = "const _attackerCounter = {};"
_END = "let _topAttackersTimer = null;"


def _counter_source():
    """실제 파일에서 집계 로직 구간만 잘라낸다."""
    src = OVERVIEW.read_text(encoding="utf-8")
    start, end = src.index(_START), src.index(_END)
    assert start < end
    return src[start:end]


# ─────────────── 정적 검사 (node 불필요) ───────────────

def test_attacker_counter_is_only_mutated_through_tracker():
    """직접 대입이 다시 생기면 상한이 무력화된다."""
    offenders = []
    for path in (OVERVIEW, RESPONSE_INIT):
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if re.search(r"_attackerCounter\[[^\]]+\]\s*(=[^=]|\.count\+\+)", line):
                # trackAttacker 안의 정의부는 허용
                if "(_attackerCounter[srcIp] = " in line:
                    continue
                offenders.append(f"{path.name}:{i}")
    assert offenders == [], (
        f"_attackerCounter 를 직접 건드리는 곳: {offenders}\n"
        f"— trackAttacker() 를 쓸 것. 직접 대입하면 상한이 무력화된다.")


def test_top_attackers_render_is_throttled():
    """매 알림마다 전량 sort 하면 폭주 시 화면이 정렬만 한다."""
    src = OVERVIEW.read_text(encoding="utf-8")
    assert "function scheduleTopAttackersRender()" in src
    # new_alert 핸들러에서 직접 부르지 않는다.
    # 파일이 IIFE 로 감싸여 들여쓰기가 바뀔 수 있으므로 닫는 줄을 정규식으로 찾는다.
    handler = src[src.index("socket.on('new_alert'"):]
    end = re.search(r"^\s*\}\);\s*$", handler, re.M)
    assert end, "new_alert 핸들러의 끝을 찾지 못했다"
    handler = handler[:end.start()]
    assert "renderTopAttackers()" not in handler, (
        "new_alert 에서 renderTopAttackers 를 직접 부른다 — "
        "scheduleTopAttackersRender() 를 쓸 것")
    assert "scheduleTopAttackersRender()" in handler


# ─────────────── 동작 검사 (node 필요) ───────────────

node = pytest.mark.skipif(shutil.which("node") is None, reason="node 없음")


def _run_js(driver):
    script = _counter_source() + "\n" + driver
    out = subprocess.run(["node", "-e", script], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, f"node 실패:\n{out.stderr}"
    return json.loads(out.stdout)


@node
def test_counter_is_bounded_under_many_unique_ips():
    """고유 IP 를 5,000개 흘려도 맵은 상한 안에 머문다."""
    result = _run_js("""
        for (let i = 0; i < 5000; i++) trackAttacker('10.0.' + (i >> 8) + '.' + (i & 255), 'DDOS');
        console.log(JSON.stringify({
          size: Object.keys(_attackerCounter).length,
          unique: uniqueAttackerCount(),
          limit: ATTACKER_MAP_LIMIT,
        }));
    """)
    assert result["size"] <= result["limit"], "상한을 넘겼다 — 누수가 남아 있다"
    # KPI 는 버린 만큼을 더해 유지된다 (각 IP 가 1회씩만 등장했으므로 정확)
    assert result["unique"] == 5000


@node
def test_eviction_keeps_the_top_attackers():
    """절단은 알림 수가 적은 IP부터 — TOP 8 표시가 목적이므로 상위권을 지킨다."""
    result = _run_js("""
        // 헤비 공격자 5명: 각 100회
        for (let r = 0; r < 100; r++)
          for (let h = 0; h < 5; h++) trackAttacker('9.9.9.' + h, 'BRUTE_FORCE');
        // 잡음 IP 5,000개: 각 1회
        for (let i = 0; i < 5000; i++) trackAttacker('10.0.' + (i >> 8) + '.' + (i & 255), 'PORT_SCAN');
        const top = Object.entries(_attackerCounter)
          .sort((a, b) => b[1].count - a[1].count).slice(0, 5).map(e => e[0]);
        console.log(JSON.stringify({ top, size: Object.keys(_attackerCounter).length }));
    """)
    assert sorted(result["top"]) == [f"9.9.9.{i}" for i in range(5)], (
        f"헤비 공격자가 절단에 쓸려나갔다: {result['top']}")


@node
def test_counting_and_type_update_still_work():
    """상한을 넣느라 원래 집계가 망가지면 안 된다."""
    result = _run_js("""
        trackAttacker('1.2.3.4', 'PORT_SCAN');
        trackAttacker('1.2.3.4', 'DDOS');
        trackAttacker('5.6.7.8', 'BRUTE_FORCE');
        trackAttacker('', 'IGNORED');          // 빈 IP 는 무시
        console.log(JSON.stringify({
          count: _attackerCounter['1.2.3.4'].count,
          type: _attackerCounter['1.2.3.4'].type,
          unique: uniqueAttackerCount(),
          hasEmpty: '' in _attackerCounter,
        }));
    """)
    assert result["count"] == 2
    assert result["type"] == "DDOS"       # 최신 위협 유형으로 갱신
    assert result["unique"] == 2
    assert result["hasEmpty"] is False


# ══════════════════════════════════════════════════════════════════
#  XSS 이스케이프 (docs/AUDIT.md C-6 / #15)
# ══════════════════════════════════════════════════════════════════
#
# 감사 시점에 **확증된 공격 경로는 없었다.** 공격자가 제어하는 필드(syslog
# message, 허니팟 payload, 접근로그 request, cmdline)는 전부 이스케이프되어
# 있었다. 문제는 "안전하다"가 아니라 **"우연히 안전하다"** 는 것이었다 —
# `src_ip`·`threat_type` 같은 서버 생성 열거형은 이스케이프 없이 렌더됐고,
# 새 이벤트 소스가 거기에 자유 문자열을 넣는 순간 조용히 XSS 가 된다.
#
# 이 테스트는 그 상태가 되돌아가지 않게 한다. 서버 데이터 문자열이 HTML 로
# 들어가는데 이스케이프가 없으면 실패한다. 아래 allowlist 는 **HTML sink 가
# 아니거나 클라이언트 상수라서 이스케이프가 불필요/유해한** 곳이다.

_STRING_FIELDS = (
    "src_ip", "dst_ip", "ip", "threat_type", "threat_label", "type", "name",
    "description", "message", "host", "hostname", "user", "username", "path",
    "rule", "rule_id", "label", "actor", "target", "detail", "payload",
    "command", "cmdline", "process", "service", "country", "city", "tactic",
    "technique", "technique_id", "tactic_id", "technique_ko", "tactic_ko",
    "reason", "note", "assignee", "origin", "verdict", "status", "severity",
    "event_id", "signature", "sid", "src", "dst", "url", "domain", "hash",
    "value", "title", "summary", "category", "source", "ko", "tactic_name",
)

# (파일, 표현식) → 이스케이프하지 않는 이유. 전부 코드를 열어 확인한 것이다.
_ESCAPE_EXEMPT = {
    ("02-overview.js", "meta.label"):        "클라이언트 라이브스트림 종류 맵",
    ("06-sources.js", "meta.label"):         "클라이언트 authlog 종류 맵",
    ("10-health.js", "m.label"):             "클라이언트 모드 맵",
    ("13-watchlist.js", "m.label"):          "클라이언트 IOC 종류 맵",
    ("06-sources.js", "s.label"):            "클라이언트 파이프라인 단계 상수",
    ("03-detection.js", "DEFENDER.label"):   "클라이언트 상수(방어 지점 라벨)",
    ("08-response-init.js", "k.ko"):         "클라이언트 플레이북 단계 종류 맵",
    ("03-detection.js", "alert.severity"):   "item.className 대입 — HTML 파싱 아님",
    ("05-svg-intel.js", "entry.tactic_id"):  "querySelector 선택자 — HTML sink 아님",
    ("05-svg-intel.js", "entry.technique_id"): "querySelector 선택자 — HTML sink 아님",
    ("06-sources.js", "e.ip"):               "raw 문자열 조립 — sink 에서 escapeHtml(raw)",
    ("06-sources.js", "e.status"):           "raw 문자열 조립 — sink 에서 escapeHtml(raw)",
    ("06-sources.js", "det.process"):        "box() 헬퍼가 내부에서 escapeHtml",
    ("06-sources.js", "r.detail"):           "alert() — HTML 아님",
    ("07-ops.js", "job.status"):             "out.textContent — HTML 아님",
    ("07-ops.js", "d.path"):                 "out.textContent — HTML 아님",
    ("08-response-init.js", "e.message"):    "alert() — HTML 아님",
    ("08-response-init.js", "inc.title"):    "title.textContent — HTML 아님",
}


def _unescaped_data_interpolations():
    pat = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*(?:\.[a-z_][\w]*)+|\bip\b)\s*\}")
    found = set()
    for path in sorted((REPO / "static" / "js" / "dash").glob("*.js")):
        src = path.read_text(encoding="utf-8")
        for m in pat.finditer(src):
            expr = m.group(1)
            if expr.split(".")[-1] not in _STRING_FIELDS:
                continue
            found.add((path.name, expr))
    return found


def test_server_strings_reaching_html_are_escaped():
    """새로 추가된 서버 데이터 렌더는 escapeHtml 을 거쳐야 한다."""
    leftover = _unescaped_data_interpolations() - set(_ESCAPE_EXEMPT)
    assert leftover == set(), (
        "이스케이프 없이 렌더되는 서버 데이터: "
        + ", ".join(f"{f}:${{{e}}}" for f, e in sorted(leftover))
        + "\n— escapeHtml() 로 감싸거나, HTML sink 가 아니라면 "
          "_ESCAPE_EXEMPT 에 이유와 함께 추가할 것.")


def test_escape_exemptions_are_all_still_real():
    """면제 목록이 낡으면 다음 사람이 '검토됐다'고 오해한다."""
    stale = set(_ESCAPE_EXEMPT) - _unescaped_data_interpolations()
    assert stale == set(), (
        f"이미 사라졌거나 이스케이프된 면제 항목: {sorted(stale)}\n"
        f"— _ESCAPE_EXEMPT 에서 제거할 것.")
