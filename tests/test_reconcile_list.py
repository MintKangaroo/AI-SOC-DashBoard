"""reconcileList — 키 기반 목록 조정이 **노드 정체성을 유지**하는지 실제 브라우저로 확인.

이 헬퍼의 존재 이유는 "바뀌지 않은 항목의 DOM 노드를 그대로 둔다" 는 것이다.
그래야 분석가가 읽던 행·드래그한 텍스트·포커스가 갱신 때 살아남는다.
문자열 비교로는 이걸 검증할 수 없다 — 같은 HTML 이라도 새 노드면 실패다.
그래서 노드에 표식을 달아 두고 갱신 뒤에도 같은 노드에 남아 있는지 본다.

크롬 headless 가 없으면 건너뛴다(CI 는 puppeteer 캐시가 없을 수 있다).
"""
import glob
import json
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
CORE = REPO / "static" / "js" / "dash" / "01-core.js"


def _chrome():
    cands = glob.glob(str(pathlib.Path.home() / ".cache/puppeteer/chrome-headless-shell/*/chrome-headless-shell-linux64/chrome-headless-shell"))
    cands += glob.glob(str(pathlib.Path.home() / ".cache/puppeteer/chrome/*/chrome-linux64/chrome"))
    return sorted(cands)[-1] if cands else None


PAGE = """<!doctype html><meta charset="utf-8">
<nav id="sidebar"></nav><main id="main-content"></main>
<div id="a11y-announcer"></div><div id="a11y-alarm"></div><span id="current-time"></span>
<ul id="list"></ul>
<script>
// 01-core.js 는 최상위에서 io() 로 소켓을 연다 — 실제 서버 없이 돌리므로 스텁
window.io = () => ({ on(){}, emit(){}, off(){} });
</script>
<script>%s</script>
<script>
const box = document.getElementById('list');
const render = it => `<li>${it.k}:${it.v}</li>`;
const out = {};
reconcileList(box, [{k:'a',v:1},{k:'b',v:1},{k:'c',v:1}], it=>it.k, render, {sig: it=>String(it.v)});
const a0 = box.children[0], b0 = box.children[1], c0 = box.children[2];
a0.__mark = 'A'; b0.__mark = 'B'; c0.__mark = 'C';
out.initial = [...box.children].map(e=>e.textContent);

// 1) 새 항목을 맨 앞에 끼워도 기존 노드는 그대로여야 한다(라이브 스트림 시나리오)
reconcileList(box, [{k:'n',v:1},{k:'a',v:1},{k:'b',v:1},{k:'c',v:1}], it=>it.k, render, {sig: it=>String(it.v)});
out.afterPrepend = [...box.children].map(e=>e.textContent);
out.prependKeepsNodes = box.children[1]===a0 && box.children[2]===b0 && box.children[3]===c0;
out.marksSurvive = box.children[1].__mark==='A' && box.children[3].__mark==='C';

// 2) 순서가 바뀌면 노드를 옮기되 새로 만들지 않는다(TOP 공격자 시나리오)
reconcileList(box, [{k:'c',v:1},{k:'a',v:1},{k:'b',v:1}], it=>it.k, render, {sig: it=>String(it.v)});
out.afterReorder = [...box.children].map(e=>e.textContent);
out.reorderKeepsNodes = box.children[0]===c0 && box.children[1]===a0 && box.children[2]===b0;
out.droppedRemoved = ![...box.children].some(e=>e.textContent.startsWith('n:'));

// 3) 서명이 바뀐 항목만 다시 그린다 — 나머지는 그대로
reconcileList(box, [{k:'c',v:1},{k:'a',v:2},{k:'b',v:1}], it=>it.k, render, {sig: it=>String(it.v)});
out.changedRerendered = box.children[1].textContent==='a:2' && box.children[1]!==a0;
out.unchangedKept = box.children[0]===c0 && box.children[2]===b0;

document.title = 'RESULT:' + JSON.stringify(out);
</script>"""


@pytest.mark.skipif(_chrome() is None, reason="크롬 headless 없음")
def test_reconcile_preserves_node_identity(tmp_path):
    html = PAGE % CORE.read_text(encoding="utf-8")
    page = tmp_path / "t.html"
    page.write_text(html, encoding="utf-8")
    proc = subprocess.run(
        [_chrome(), "--headless", "--no-sandbox", "--disable-gpu",
         "--virtual-time-budget=2000", "--dump-dom", page.as_uri()],
        capture_output=True, text=True, timeout=60)
    dom = proc.stdout
    # 스크립트 원문에도 'RESULT:' 리터럴이 있으므로 <title> 안의 것만 찾는다.
    start = dom.find("<title>RESULT:")
    assert start != -1, f"결과 마커 없음 — 스크립트 오류?\n{proc.stderr[-800:]}"
    payload = dom[start + len("<title>RESULT:"):]
    payload = payload[:payload.index("</title>")]
    import html as _h
    out = json.loads(_h.unescape(payload))

    assert out["initial"] == ["a:1", "b:1", "c:1"]
    assert out["afterPrepend"] == ["n:1", "a:1", "b:1", "c:1"]
    assert out["prependKeepsNodes"], "앞에 끼웠는데 기존 노드가 새로 만들어졌다 — 선택·포커스가 날아간다"
    assert out["marksSurvive"], "노드 표식이 사라졌다 — 같은 노드가 아니다"
    assert out["afterReorder"] == ["c:1", "a:1", "b:1"]
    assert out["reorderKeepsNodes"], "순서만 바뀌었는데 노드를 새로 만들었다"
    assert out["droppedRemoved"], "목록에서 빠진 항목이 DOM 에 남아 있다"
    assert out["changedRerendered"], "서명이 바뀐 항목이 다시 그려지지 않았다"
    assert out["unchangedKept"], "서명이 그대로인 항목까지 새로 만들었다"
