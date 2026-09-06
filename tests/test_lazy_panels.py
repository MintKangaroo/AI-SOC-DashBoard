"""패널 지연 실체화 (UI/UX 감사 마지막 항목 — DOM 7,079 노드).

36개 패널이 전부 상주하던 첫 화면을, 개요만 실제 DOM 으로 내리고 나머지 35개는
`<template data-panel="이름">` 에 담아 보내는 구조로 바꿨다. template 내용은 문서
트리에 속하지 않으므로(inert) 파싱만 되고 스타일·레이아웃·getElementById 비용이
없다. 처음 열 때 `materializePanel()` 이 꺼내 놓는다(01-core.js).

이 구조의 실패 모드는 전부 **조용하다** — 콘솔에만 남고 화면은 그냥 안 바뀐다:
1. 새 패널을 include 로만 추가하면 상주 패널이 되어 감축이 새는데, 동작은 한다.
2. 소켓 핸들러가 `getElementById('panel-x')?.classList.contains('d-none')` 로
   가시성을 판단하면 **없는 패널을 '보인다'로 오판**해 loadX() 를 불러 null 참조.
3. `DOMContentLoaded` 에서 패널 안 요소에 리스너를 달면 요소가 아직 없어서 조용히
   빠진다 — `onPanelReady(이름, fn)` 을 써야 한다.
4. 패널 파일의 루트 id 가 파일명과 다르면 materialize 는 되지만 showPanel 이 못 찾는다.
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
DASH = (REPO / "templates" / "dashboard.html").read_text(encoding="utf-8")
PANEL_DIR = REPO / "templates" / "panels"
JS_DIR = REPO / "static" / "js" / "dash"

RESIDENT = {"overview"}   # 첫 화면. 최상위에서 차트 컨텍스트를 잡는다.

_INCLUDE = re.compile(r'(<template data-panel="([a-z-]+)">)?\{% include "panels/([a-z-]+)\.html" %\}')


def _includes():
    return [(m.group(2), m.group(3)) for m in _INCLUDE.finditer(DASH)]


def _panel_ids(name):
    src = (PANEL_DIR / f"{name}.html").read_text(encoding="utf-8")
    return set(re.findall(r'\bid="([^"]+)"', src))


def test_every_panel_except_overview_is_wrapped_in_a_template():
    incs = _includes()
    assert len(incs) >= 30, "include 를 못 읽었다 — 정규식이 템플릿과 어긋난 것"
    bad = [(tpl, name) for tpl, name in incs
           if (name in RESIDENT) != (tpl is None) or (tpl and tpl != name)]
    assert bad == [], (
        f"template 래핑이 어긋난 패널: {bad}\n"
        f'— 상주 패널({RESIDENT})은 맨 include, 나머지는 '
        f'<template data-panel="이름">{{% include %}}</template> 로 감싸고 이름을 맞출 것.')


def test_every_sidebar_link_has_a_panel():
    linked = set(re.findall(r'data-panel="([a-z-]+)"', DASH.split("<main")[0]))
    provided = {name for _tpl, name in _includes()}
    assert linked - provided == set(), f"사이드바만 있고 패널이 없다: {linked - provided}"


def test_panel_root_id_matches_file_name():
    for _tpl, name in _includes():
        src = (PANEL_DIR / f"{name}.html").read_text(encoding="utf-8")
        first = re.search(r'<(?:div|section)\b[^>]*\bid="panel-([a-z-]+)"[^>]*class="[^"]*\bpanel-section\b', src)
        assert first and first.group(1) == name, (
            f"panels/{name}.html 의 루트가 id=\"panel-{name}\" class=\"panel-section\" 이 아니다 "
            f"— materializePanel/showPanel 이 이 규약으로 찾는다.")


def test_no_optional_chaining_visibility_check_on_panels():
    """없는 패널을 '보인다'로 오판하는 패턴. isPanelVisible() 을 쓸 것."""
    pat = re.compile(r"getElementById\(['\"]panel-[a-z-]+['\"]\)\s*\??\.classList\.contains\(['\"]d-none['\"]\)")
    hits = [f"{p.name}:{i}" for p in sorted(JS_DIR.glob("*.js"))
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if pat.search(line)]
    assert hits == [], (
        f"패널 가시성을 classList 로 직접 판단: {hits}\n"
        f"— 실체화 전에는 요소가 없어 `?.` 가 undefined 를 주고 `!undefined` 는 '보인다'가 된다. "
        f"isPanelVisible('이름') 을 쓸 것.")


def test_domcontentloaded_does_not_reach_into_lazy_panels():
    """DOMContentLoaded 시점엔 지연 패널 요소가 없다 — onPanelReady 로 옮길 것."""
    lazy_ids = {}
    for _tpl, name in _includes():
        if name in RESIDENT:
            continue
        for i in _panel_ids(name):
            lazy_ids[i] = name
    offenders = []
    for p in sorted(JS_DIR.glob("*.js")):
        lines = p.read_text(encoding="utf-8").splitlines()
        for start, line in enumerate(lines):
            if "DOMContentLoaded" not in line or "addEventListener" not in line:
                continue
            block = []
            for l in lines[start:]:
                block.append(l)
                if re.match(r"^  \}\);\s*$", l):
                    break
            for i in re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", "\n".join(block)):
                if i in lazy_ids:
                    offenders.append(f"{p.name}:{start + 1} #{i} (panels/{lazy_ids[i]}.html)")
    assert offenders == [], (
        f"DOMContentLoaded 에서 지연 패널 요소를 잡는다: {offenders}\n"
        f"— 그 시점엔 요소가 없다. onPanelReady('패널', () => {{...}}) 로 옮길 것.")


def test_core_exposes_materialization_api():
    core = (JS_DIR / "01-core.js").read_text(encoding="utf-8")
    assert "function materializePanel" in core and "function onPanelReady" in core
    assert re.search(r"function showPanel\(name\) \{\s*materializePanel\(name\);", core), \
        "showPanel 은 첫 줄에서 materializePanel 을 불러야 한다"
    # 딥링크: template 상태인 패널도 '있는' 패널이다.
    assert 'template[data-panel=' in core.split("function panelFromHash")[0].split("function panelExists")[1]
