"""프런트엔드 전역 네임스페이스 (docs/AUDIT.md E-2 / #23).

18개 파일이 `<script>` 로 순서대로 로드되고 최상위 선언이 335개였다. 모듈
시스템이 없으니 **같은 이름을 두 파일이 `let`/`const` 로 선언하면 로드 시점에
SyntaxError 로 대시보드 전체가 죽는다.** 감사 시점에 충돌은 없었지만, 새 패널을
추가할 때마다 그 위험을 감수하는 구조였다.

감사는 `<script type="module">` 전면 전환을 **"지금은 하지 말 것"** 으로 판정했다
(18파일 대공사인데 얻는 게 안전성뿐). 대안으로 제시된 IIFE 점진 적용을 택했다 —
각 파일을 즉시실행함수로 감싸고 `Object.assign(window, {...})` 로 공개 표면만
명시한다.

여기서 지키는 것:
1. 최상위 이름 충돌 0 — 충돌이 생기면 CI 에서 죽지, 브라우저에서 죽지 않는다.
2. 모든 파일이 IIFE 로 감싸여 있다.
3. **인라인 핸들러·파일간 참조가 필요로 하는 이름이 전부 공개되어 있다.**
   이게 IIFE 전환의 유일한 실패 모드다 — 빠뜨리면 클릭이 조용히 죽는다.
"""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
JS_DIR = REPO / "static" / "js" / "dash"
TPL_DIR = REPO / "templates"
HARNESS = REPO / "tests" / "js" / "load_dashboard.js"

# IIFE 안의 최상위 = 정확히 2칸 들여쓰기. 3칸 이상은 함수 내부 지역변수다.
_TOP_DECL = re.compile(r"^  (?:async )?(function|const|let|var|class)\s+([A-Za-z_$][\w$]*)")
_HANDLER = re.compile(r'\bon[a-z]+\s*=\s*[\\"\'"]([^"\'`]{0,400}?)[\\"\'"]')
_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")


def _sources():
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(JS_DIR.glob("*.js"))}


def _top_level_declarations(src):
    return [(m.group(2), m.group(1))
            for line in src.split("\n") if (m := _TOP_DECL.match(line))]


def _owner_map(srcs):
    owner = {}
    for fname, src in srcs.items():
        for name, _kind in _top_level_declarations(src):
            owner[name] = fname
    return owner


def _required_globals(srcs):
    """인라인 핸들러·파일간 참조가 실제로 필요로 하는 이름."""
    owner = _owner_map(srcs)
    required = set()

    def scan_handlers(text):
        for handler in _HANDLER.finditer(text):
            for call in _CALL.finditer(handler.group(1)):
                if call.group(1) in owner:
                    required.add(call.group(1))

    for tpl in TPL_DIR.rglob("*.html"):
        scan_handlers(tpl.read_text(encoding="utf-8"))
    for src in srcs.values():
        scan_handlers(src)          # JS 가 생성하는 마크업의 핸들러도 포함해야 한다

    for name, home in owner.items():
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        if any(pattern.search(srcs[other]) for other in srcs if other != home):
            required.add(name)
    return required


# ─────────────── 정적 검사 ───────────────

def test_no_top_level_name_collisions():
    """두 파일이 같은 이름을 최상위에 선언하면 브라우저가 로드 중에 죽는다."""
    seen = {}
    collisions = {}
    for fname, src in _sources().items():
        for name, kind in _top_level_declarations(src):
            if name in seen:
                collisions.setdefault(name, [seen[name]]).append((fname, kind))
            else:
                seen[name] = (fname, kind)
    assert collisions == {}, (
        f"최상위 이름 충돌: {collisions}\n"
        f"— const/let/class 충돌은 로드 시 SyntaxError 로 대시보드 전체를 죽인다.")


def test_every_dash_file_is_wrapped_in_an_iife():
    """감싸지 않은 파일이 하나라도 있으면 그 파일의 선언이 전부 전역이 된다."""
    unwrapped = []
    for path in sorted(JS_DIR.glob("*.js")):
        src = path.read_text(encoding="utf-8")
        # 선두 블록/줄 주석과 빈 줄을 걷어낸 뒤 첫 코드가 IIFE 여야 한다
        body = re.sub(r"\A(?:\s*(?:/\*.*?\*/|//[^\n]*)\s*)+", "", src, flags=re.S)
        if not body.startswith("(function () {"):
            unwrapped.append(path.name)
    assert unwrapped == [], (
        f"IIFE 로 감싸지 않은 파일: {unwrapped}\n"
        f"— `(function () {{ ... }})();` 로 감싸고 공개 이름만 "
        f"`Object.assign(window, {{...}})` 로 노출할 것.")


def test_public_surface_is_smaller_than_total_declarations():
    """공개 표면이 전체 선언과 같아지면 감싼 의미가 없다."""
    srcs = _sources()
    total = sum(len(_top_level_declarations(s)) for s in srcs.values())
    public = len(_required_globals(srcs))
    assert total > 0
    assert public < total * 0.6, (
        f"전역이 충분히 줄지 않았다: 선언 {total} 중 {public} 공개")


# ─────────────── 실제 로드 검사 (node 필요) ───────────────

node = pytest.mark.skipif(shutil.which("node") is None, reason="node 없음")


@node
def test_all_files_load_and_export_what_handlers_need(tmp_path):
    """18개를 순서대로 로드하고, 필요한 이름이 window 에 있는지 확인한다.

    IIFE 전환의 유일한 실패 모드가 여기서 잡힌다 — 공개를 빠뜨린 함수는
    인라인 핸들러가 부를 수 없고, 그 실패는 브라우저에서 조용하다.
    """
    required = sorted(_required_globals(_sources()))
    assert required, "필요한 전역을 하나도 못 찾았다 — 검사기가 고장난 것"
    req_file = tmp_path / "required.json"
    req_file.write_text(json.dumps(required), encoding="utf-8")

    out = subprocess.run(["node", str(HARNESS), str(JS_DIR), str(req_file)],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, f"하네스 실행 실패:\n{out.stderr}"
    result = json.loads(out.stdout)

    assert result["loadFailures"] == [], (
        f"로드 중 예외: {result['loadFailures']}")
    assert result["missingAfterLoad"] == [], (
        f"핸들러·다른 파일이 필요로 하는데 공개되지 않은 이름: "
        f"{result['missingAfterLoad']}\n"
        f"— 해당 파일의 Object.assign(window, {{...}}) 에 추가할 것.")
