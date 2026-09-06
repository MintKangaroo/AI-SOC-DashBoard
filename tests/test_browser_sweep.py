"""실제 브라우저로 36개 패널을 전부 열어 본다.

pytest 821건·ruff·GET 라우트 56개 스모크가 전부 초록인 날, 이 방식(Playwright 로
사이드바 순회)만이 결함 3건을 잡았다 — `/api/metrics/soc` 의 스레드 경합 500
(딕셔너리 순회 중 인시던트 추가), favicon 404 가 페이지마다 콘솔 오류, 모바일
390px 에서 제목 줄 컨트롤이 화면 밖으로 잘림. 셋 다 test_client 가 원리적으로
못 보는 종류다: 스레드 경합, 브라우저의 리소스 요청, 실제 레이아웃.

여기서 재는 것(데스크톱 1400px · 모바일 390px 각각):
- 콘솔 error / 처리되지 않은 예외 — 0 이어야 한다
- 상태 400 이상 응답 — 0 이어야 한다
- 패널을 열었을 때 본문(main-content)의 가로 넘침 — 0px 이어야 한다.
  넘치면 모바일에서 제목·탭이 화면 밖으로 나가고, 잘린 버튼은 누를 수 없다
- showPanel(이름) 뒤에 실제로 그 패널이 보이는지(지연 실체화 회귀)

서버는 test_live_server 의 fixture 를 그대로 쓴다 — 빈 임시 디렉터리에서 실제
프로세스로 뜬다. 크롬이 없으면 건너뛴다(CI 는 `playwright install chromium`).
"""
import glob
import os
import pathlib

import pytest

# fixture 재사용 — pytest 는 모듈 속성 이름으로 fixture 를 등록하므로 별칭을 쓰면 안 된다.
from tests.test_live_server import live  # noqa: F401

pytestmark = [pytest.mark.live, pytest.mark.browser]

try:
    from playwright.sync_api import Error as PWError
    from playwright.sync_api import sync_playwright
except ImportError:          # pragma: no cover
    sync_playwright = None

PANEL_SETTLE_MS = 700        # 패널 로더(fetch)와 첫 렌더가 끝나기를 기다리는 시간
SOCKET_LISTEN_MS = 4000      # 개요에서 실시간 이벤트를 받아 핸들러 오류를 보는 시간
VIEWPORTS = {"desktop": (1400, 900), "mobile": (390, 844)}

# 브라우저가 자기 사정으로 내는 잡음 — 제품 결함이 아니다
_NOISE = ("net::ERR_ABORTED",)


def _puppeteer_chrome():
    cands = sorted(glob.glob(str(pathlib.Path.home()
                                 / ".cache/puppeteer/chrome/*/chrome-linux64/chrome")))
    return cands[-1] if cands else None


def _launch(pw):
    """Playwright 자체 chromium → puppeteer 캐시 순서. 둘 다 없으면 skip."""
    try:
        return pw.chromium.launch(args=["--no-sandbox"])
    except PWError:
        pass
    exe = _puppeteer_chrome()
    if exe and os.path.exists(exe):
        return pw.chromium.launch(executable_path=exe, args=["--no-sandbox"])
    pytest.skip("크롬 없음 — `python -m playwright install chromium`")


_OVERFLOW_JS = """() => {
  const m = document.getElementById('main-content');
  const shown = document.querySelector('.panel-section:not(.d-none)');
  return { overflow: m.scrollWidth - m.clientWidth, shown: shown ? shown.id : null };
}"""


def _sweep(live, width, height):  # noqa: F811
    findings = []
    with sync_playwright() as pw:
        browser = _launch(pw)
        try:
            page = browser.new_page(viewport={"width": width, "height": height})
            page.on("console", lambda m: m.type == "error"
                    and not any(n in m.text for n in _NOISE)
                    and findings.append(f"console: {m.text[:200]} @ {m.location.get('url', '')[-80:]}"))
            page.on("pageerror", lambda e: findings.append(f"pageerror: {str(e)[:200]}"))
            page.on("response", lambda r: r.status >= 400
                    and findings.append(f"http {r.status}: {r.url[-100:]}"))

            page.goto(live["base"] + "/", wait_until="load")
            page.wait_for_timeout(2000)
            names = page.eval_on_selector_all(
                ".sidebar-link[data-panel]", "els => els.map(e => e.dataset.panel)")
            names = list(dict.fromkeys(names))
            assert len(names) >= 30, f"사이드바 패널 링크가 {len(names)}개뿐 — 셀렉터가 어긋난 것"

            for name in names:
                page.evaluate("n => showPanel(n)", name)
                page.wait_for_timeout(PANEL_SETTLE_MS)
                st = page.evaluate(_OVERFLOW_JS)
                if st["shown"] != f"panel-{name}":
                    findings.append(f"{name}: showPanel 뒤 보이는 패널이 {st['shown']}")
                if st["overflow"] > 0:
                    findings.append(f"{name}: 본문 가로 넘침 {st['overflow']}px @ {width}px")

            # 개요로 돌아와 실시간 이벤트를 받는다 — 소켓 핸들러의 오류가 여기서 난다
            page.evaluate("showPanel('overview')")
            page.wait_for_timeout(SOCKET_LISTEN_MS)
        finally:
            browser.close()
    return names, findings


@pytest.mark.skipif(sync_playwright is None, reason="playwright 미설치")
@pytest.mark.parametrize("label", list(VIEWPORTS))
def test_every_panel_opens_clean(live, label):  # noqa: F811
    width, height = VIEWPORTS[label]
    names, findings = _sweep(live, width, height)
    assert findings == [], (
        f"[{label} {width}px] 패널 {len(names)}개 순회 중 발견:\n  " + "\n  ".join(findings))
