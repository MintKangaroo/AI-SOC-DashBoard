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
    # new_alert 핸들러에서 직접 부르지 않는다
    handler = src[src.index("socket.on('new_alert'"):]
    handler = handler[:handler.index("\n});")]
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
