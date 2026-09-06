"""글자 크기 역할 스케일 가드.

한때 px 값이 CSS 29종·템플릿 16종·JS 7종으로 흩어져 있었다(8~36px, 0.5 단위).
같은 역할이 화면마다 다른 크기로 나오면 위계가 흐려진다. 크기는 :root 의
--fs-* 토큰으로만 정하고, 다른 곳에서는 토큰을 참조한다.
"""
import glob
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
CSS = (REPO / "static/css/style.css").read_text(encoding="utf-8")
_PX = re.compile(r"font-size:\s*[0-9.]+(px|rem|em)")   # rem/em 드리프트도 잡는다
_DEF = re.compile(r"^\s*--fs-[a-z0-9-]+\s*:\s*([0-9.]+)px", re.M)


def test_scale_is_defined_and_monotonic():
    sizes = [float(v) for v in _DEF.findall(CSS)]
    assert len(sizes) >= 8, "역할 스케일 토큰이 너무 적다"
    assert sizes == sorted(sizes), "스케일이 단조 증가하지 않는다"
    assert min(sizes) >= 9, "9px 아래는 관제 모니터에서도 안 읽힌다"


def test_no_raw_pixel_font_size_outside_scale():
    """토큰 정의 줄 밖의 px 글자 크기는 드리프트다."""
    offenders = []
    for i, ln in enumerate(CSS.split("\n"), 1):
        if _DEF.match(ln):
            continue
        if _PX.search(ln):
            offenders.append(f"style.css:{i}: {ln.strip()[:80]}")
    files = [f for f in glob.glob(str(REPO / "templates/**/*.html"), recursive=True)
             if not f.endswith("login.html")]           # 독립 페이지 — 자체 스타일
    files += glob.glob(str(REPO / "static/js/dash/*.js"))
    for f in files:
        for i, ln in enumerate(pathlib.Path(f).read_text(encoding="utf-8").split("\n"), 1):
            if _PX.search(ln):
                offenders.append(f"{pathlib.Path(f).name}:{i}: {ln.strip()[:80]}")
    assert offenders == [], (
        "역할 토큰(var(--fs-*)) 대신 px 를 직접 쓴 곳:\n  " + "\n  ".join(offenders[:20]))
