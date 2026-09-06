"""CSS 토큰 정의 가드 — 페이지가 참조하는 var(--x) 는 **그 페이지가 실제로 로드하는**
스타일시트에 정의돼 있어야 한다.

실측으로 드러난 구멍: 토큰 회수 작업이 templates/**/*.html 전체의 hex 를
var(--…) 로 바꿨는데, login.html 은 style.css 를 로드하지 않는 독립 페이지라
정의가 없었다. 배경이 흰색, 글자가 검정, 입력칸이 투명으로 떨어졌고 테스트
793건 중 하나도 못 잡았다 — 사용자가 폰에서 발견했다.

CSS 는 정의 없는 var() 를 오류 없이 상속값·초기값으로 떨어뜨리므로, 눈으로
보기 전엔 아무도 모른다. 그래서 여기서 페이지 단위로 대조한다.
"""
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
TPL = REPO / "templates"
STYLE = REPO / "static" / "css" / "style.css"

_DEF = re.compile(r"(--[A-Za-z0-9-]+)\s*:")
_USE = re.compile(r"var\(\s*(--[A-Za-z0-9-]+)")
_INLINE_STYLE = re.compile(r"<style[^>]*>(.*?)</style>", re.S)
_LINKED_CSS = re.compile(r'href="(/static/css/[^"]+)"')
_INCLUDE = re.compile(r'{%\s*include\s+"([^"]+)"\s*%}')
_SCRIPT = re.compile(r'src="(/static/js/[^"]+)"')


def _read(path):
    return path.read_text(encoding="utf-8")


def _expand_includes(html, seen=None):
    """Jinja include 를 따라가 한 페이지가 실제로 렌더하는 마크업을 모은다."""
    seen = seen or set()
    out = html
    for name in _INCLUDE.findall(html):
        if name in seen:
            continue
        seen.add(name)
        out += "\n" + _expand_includes(_read(TPL / name), seen)
    return out


def _tokens_defined_for(page_html):
    """이 페이지가 로드하는 스타일시트(외부 + 인라인)에서 정의된 토큰."""
    defined = set()
    for href in _LINKED_CSS.findall(page_html):
        defined |= set(_DEF.findall(_read(REPO / href.lstrip("/"))))
    for block in _INLINE_STYLE.findall(page_html):
        defined |= set(_DEF.findall(block))
    return defined


def _tokens_used_in(page_html):
    """마크업(인라인 style·인라인 <style>)과 이 페이지가 로드하는 JS 가 참조하는 토큰."""
    used = set(_USE.findall(page_html))
    for src in _SCRIPT.findall(page_html):
        p = REPO / src.lstrip("/")
        if p.is_file():
            used |= set(_USE.findall(_read(p)))
    return used


# 코드 주석 안 예시(`var(--x)`)처럼 실제 참조가 아닌 것
_DOC_ONLY = {"--x"}


@pytest.mark.parametrize("page", sorted(p.name for p in TPL.glob("*.html")))
def test_every_token_a_page_uses_is_defined_for_that_page(page):
    html = _expand_includes(_read(TPL / page))
    defined = _tokens_defined_for(html)
    used = _tokens_used_in(html) - _DOC_ONLY
    assert defined, f"{page}: 스타일시트를 하나도 못 찾았다 — 검사기가 고장난 것"
    missing = sorted(used - defined)
    assert missing == [], (
        f"{page} 가 참조하지만 이 페이지가 로드하는 스타일시트에 정의가 없는 토큰: "
        f"{missing}\n— 독립 페이지라면 그 페이지의 <style> 에 정의하고, "
        f"공용이면 style.css 에 정의할 것. CSS 는 이걸 오류로 알려주지 않는다.")


def test_root_defines_no_token_twice_with_different_values():
    """**전역(:root)** 토큰이 다른 값으로 두 번 정의되면 뒤의 것이 이기는데, 그게
    의도인지 아무도 모른다.

    검사 범위를 :root 블록으로 한정하는 이유: --sev / --note-accent / --kpi-accent
    처럼 선택자마다 덮어쓰라고 만든 컴포넌트 범위 변수가 있다. 그건 중복이
    아니라 설계다. 처음엔 파일 전체를 훑어서 그걸 17건 오탐으로 잡았다.
    """
    css = _read(STYLE)
    roots = "\n".join(re.findall(r":root\s*{([^}]*)}", css))
    assert roots, ":root 블록을 못 찾았다 — 검사기가 고장난 것"
    seen = {}
    dup = []
    for m in re.finditer(r"(--[A-Za-z0-9-]+)\s*:\s*([^;]+);", roots):
        name, val = m.group(1), m.group(2).strip()
        if name in seen and seen[name] != val:
            dup.append((name, seen[name], val))
        seen.setdefault(name, val)
    assert dup == [], f"값이 다른 중복 정의: {dup}"
