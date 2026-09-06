"""색 대비 회귀 고정 — 심각도 색은 이 대시보드에서 **정보를 나르는 신호**다.

실측으로 드러난 문제: 흰 글자 기준 CRITICAL 뱃지가 3.35:1, LOW 가 2.53:1 로
WCAG AA(본문 4.5:1) 미달이었다. 가장 급한 알림의 라벨이 가장 안 읽히는 상태다.
색을 바꿀 때 이게 조용히 되돌아가지 않도록 여기서 고정한다.
"""
import pathlib
import re

import pytest

CSS = (pathlib.Path(__file__).resolve().parent.parent
       / "static" / "css" / "style.css").read_text(encoding="utf-8")

AA_NORMAL = 4.5      # 본문 크기 텍스트
AA_LARGE = 3.0       # 큰 텍스트 / 비텍스트 경계


def _luminance(hex_color):
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    srgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in srgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a, b):
    la, lb = _luminance(a), _luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def resolve(value, _depth=0):
    """`var(--x)` 를 실제 색까지 따라간다.

    색을 하드코딩에서 토큰 참조로 옮기면 `color: var(--bg-primary)` 처럼 값이
    한 단계 뒤로 물러난다. hex 만 읽는 검사기는 그때 조용히 아무것도 검사하지
    않게 된다 — 그래서 참조를 끝까지 푼다.
    """
    assert _depth < 10, f"토큰 참조가 순환한다: {value}"
    value = value.strip()
    m = re.fullmatch(r"var\(\s*(--[A-Za-z0-9-]+)\s*\)", value)
    if not m:
        return value
    return resolve(token(m.group(1), raw=True), _depth + 1)


def token(name, raw=False):
    """:root 에 선언된 토큰 값을 읽는다(기본은 색까지 해석)."""
    m = re.search(rf"{re.escape(name)}\s*:\s*([^;]+);", CSS)
    assert m, f"{name} 토큰을 못 찾음"
    value = m.group(1).strip()
    return value if raw else resolve(value)


def test_var_reference_is_resolved():
    """`var()` 를 못 풀면 검사기가 조용히 통과만 하게 된다 — 그 상태를 막는다."""
    assert resolve("var(--bg-primary)") == token("--bg-primary")
    assert resolve("#123456") == "#123456"
    # 별칭 토큰(--muted → --text-muted)도 끝까지 따라간다
    assert resolve("var(--muted)") == token("--text-muted")


def test_contrast_helper_is_correct():
    """검사기 자체가 맞는지 — 알려진 값으로 검증(검사기가 고장나면 전부 통과한다)."""
    assert contrast("#ffffff", "#000000") == pytest.approx(21.0, abs=0.01)
    assert contrast("#ffffff", "#ffffff") == pytest.approx(1.0, abs=0.01)


@pytest.mark.parametrize("cls,bg_token", [
    ("sev-CRITICAL", "--red"),
    ("sev-HIGH",     "--orange"),
    ("sev-MEDIUM",   "--yellow"),
    ("sev-LOW",      "--blue"),
])
def test_severity_badge_text_meets_aa(cls, bg_token):
    """뱃지 글자가 배경 위에서 읽혀야 한다."""
    m = re.search(rf"\.{cls}\s*{{[^}}]*color:\s*([^;]+);", CSS)
    assert m, f".{cls} 의 color 를 못 찾음"
    ratio = contrast(resolve(m.group(1)), token(bg_token))
    assert ratio >= AA_NORMAL, f".{cls} 대비 {ratio:.2f}:1 — {AA_NORMAL}:1 필요"


@pytest.mark.parametrize("bg_token", ["--red", "--orange", "--yellow", "--blue"])
def test_severity_badge_visible_against_surface(bg_token):
    """뱃지 자체가 카드 배경에서 도드라져야 한다(색이 곧 신호이므로)."""
    ratio = contrast(token(bg_token), token("--bg-card"))
    assert ratio >= AA_LARGE, f"{bg_token} 뱃지가 카드 배경에 묻힌다({ratio:.2f}:1)"


@pytest.mark.parametrize("fg_token", ["--text-primary", "--text-muted"])
@pytest.mark.parametrize("bg_token", ["--bg-primary", "--bg-secondary", "--bg-card"])
def test_body_text_meets_aa(fg_token, bg_token):
    ratio = contrast(token(fg_token), token(bg_token))
    assert ratio >= AA_NORMAL, f"{fg_token} on {bg_token} = {ratio:.2f}:1"


@pytest.mark.parametrize("accent", ["--cyan", "--green", "--orange", "--red",
                                    "--yellow", "--blue", "--purple"])
def test_accent_text_meets_aa_on_dark(accent):
    """강조색은 어두운 배경 위 **글자**로도 쓰인다(수치·상태 표시)."""
    ratio = contrast(token(accent), token("--bg-card"))
    assert ratio >= AA_NORMAL, f"{accent} 글자 대비 {ratio:.2f}:1"
