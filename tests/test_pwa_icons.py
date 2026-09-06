"""홈 화면 바로가기 아이콘 — iOS Safari 는 apple-touch-icon PNG 만 쓴다.

SVG favicon 이나 manifest 아이콘은 iOS 가 무시하므로, PNG 파일과 <link> 가 둘 다
있어야 한다. 실제로 사용자가 "바로가기 아이콘이 안 예쁘다"고 제보한 것이 계기다.
"""
import json
import pathlib
import struct

REPO = pathlib.Path(__file__).resolve().parent.parent
ICONS = REPO / "static" / "icons"


def _png_size(path):
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} 은 PNG 가 아니다"
    w, h = struct.unpack(">II", data[16:24])
    return w, h


def test_icon_files_exist_with_expected_sizes():
    assert _png_size(ICONS / "apple-touch-icon.png") == (180, 180)
    assert _png_size(ICONS / "icon-192.png") == (192, 192)
    assert _png_size(ICONS / "icon-512.png") == (512, 512)


def test_manifest_points_at_existing_icons():
    m = json.loads((REPO / "static" / "site.webmanifest").read_text(encoding="utf-8"))
    assert m["display"] == "standalone" and m["short_name"]
    for icon in m["icons"]:
        assert (REPO / icon["src"].lstrip("/")).exists(), icon["src"]


def test_pages_declare_apple_touch_icon_and_manifest():
    for name in ("dashboard.html", "login.html"):
        html = (REPO / "templates" / name).read_text(encoding="utf-8")
        assert 'rel="apple-touch-icon"' in html, name
        assert "/static/icons/apple-touch-icon.png" in html, name
        assert 'rel="manifest"' in html, name
        assert 'name="apple-mobile-web-app-capable"' in html, name
