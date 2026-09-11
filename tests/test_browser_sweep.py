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


# ---------------------------------------------------------------- #
#  사이드바 메뉴가 짧은 화면에서 잘리지 않는가
# ---------------------------------------------------------------- #
#
# 위 순회는 `showPanel(이름)` 을 **직접 호출**해서 패널을 연다. 그래서 "사이드바에
# 그 메뉴가 실제로 보이고 누를 수 있는가" 는 원리적으로 못 본다. 실제로 그 틈으로
# 결함이 하나 지나갔다 — 사이드바는 세로 flex 인데 자식의 기본 `flex-shrink:1` 이
# 화면이 짧을 때 그룹 본문을 눌러버리고, `overflow:hidden` 이 눌린 만큼을 잘라냈다.
# 사이드바는 스크롤도 생기지 않아(자식이 줄어드니 넘치지 않는다) 마지막 메뉴가
# 통째로 사라져 보였다: 390×750 에서 '네트워크 관제' 1개, 414×700 에서 177px 분량.
#
# 그래서 여기서는 **사람이 하는 것과 같은 순서**로 본다 — 드로어를 열고, 그룹을
# 펼치고, 링크가 부모 밖으로 잘리지 않았는지, 그리고 그 자리를 실제로 누를 수
# 있는지(elementFromPoint) 확인한다.
SHORT_VIEWPORTS = {"mobile-short": (390, 750), "small-laptop": (1280, 620)}

_GROUPS_JS = """() => [...document.querySelectorAll('.sidebar-group[data-args]')]
  .map(b => { try { return JSON.parse(b.dataset.args)[0]; } catch (e) { return null; } })
  .filter(Boolean)"""

# ⚠ 측정 순서가 중요하다. 링크마다 `scrollIntoView` 를 부르면서 재면 **아무것도
#   못 잡는다** — `overflow:hidden` 컨테이너도 스크립트로는 스크롤되므로, 앞 링크를
#   보이게 하는 과정에서 뒤 링크가 제자리로 끌려 들어와 잘림이 사라진다(실제로 이
#   테스트의 첫 판이 그래서 결함을 통과시켰다). 그래서 **먼저 아무것도 건드리지 않고**
#   본문이 제 내용을 다 담고 있는지(scrollHeight ≤ clientHeight) 보고, 그 다음에
#   누를 수 있는지 확인한다.
_CLIP_JS = """(group) => {
  const body = document.getElementById('sgroup-' + group);
  if (!body || body.classList.contains('collapsed')) return ['그룹이 안 열림'];
  const out = [];
  const cut = body.scrollHeight - body.clientHeight;
  if (cut > 1) {
    const gone = [...body.querySelectorAll('.sidebar-link[data-panel]')]
      .filter(a => a.getBoundingClientRect().bottom > body.getBoundingClientRect().bottom + 1)
      .map(a => a.dataset.panel);
    out.push(`본문이 ${Math.round(cut)}px 잘림 — 안 보이는 메뉴: ${gone.join(', ') || '(경계)'}`);
    return out;
  }
  body.querySelectorAll('.sidebar-link[data-panel]').forEach(a => {
    a.scrollIntoView({ block: 'center' });
    const c = a.getBoundingClientRect();
    const hit = document.elementFromPoint(c.left + c.width / 2, c.top + c.height / 2);
    const reached = hit && hit.closest('a.sidebar-link');
    if (!reached || reached.dataset.panel !== a.dataset.panel)
      out.push(`${a.dataset.panel}: 그 자리를 누를 수 없음(${reached ? reached.dataset.panel : '가려짐'})`);
  });
  return out;
}"""


@pytest.mark.skipif(sync_playwright is None, reason="playwright 미설치")
@pytest.mark.parametrize("label", list(SHORT_VIEWPORTS))
def test_sidebar_menus_are_not_clipped(live, label):  # noqa: F811
    width, height = SHORT_VIEWPORTS[label]
    findings = []
    with sync_playwright() as pw:
        browser = _launch(pw)
        try:
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto(live["base"] + "/", wait_until="load")
            page.wait_for_timeout(1500)
            if width < 992:                      # 모바일은 드로어를 먼저 연다
                page.evaluate("toggleSidebar()")
                page.wait_for_timeout(400)
            groups = page.evaluate(_GROUPS_JS)
            assert groups, "사이드바 그룹을 못 찾음 — 셀렉터가 어긋난 것"
            for group in groups:                 # 아코디언이라 한 번에 하나씩 본다
                page.evaluate("g => toggleGroup(g)", group)
                page.wait_for_timeout(300)
                for problem in page.evaluate(_CLIP_JS, group):
                    findings.append(f"{group} 그룹 · {problem}")
        finally:
            browser.close()
    assert findings == [], (
        f"[{label} {width}x{height}] 사이드바 메뉴가 잘리거나 눌리지 않음:\n  "
        + "\n  ".join(findings))


# ---------------------------------------------------------------- #
#  폰 크기에서 컨트롤이 실제로 눌리는가 · 접촉 면적은 충분한가
# ---------------------------------------------------------------- #
#
# 위 두 검사는 "패널이 열리는가"와 "메뉴가 잘리지 않는가"를 본다. 정작 패널 **안**
# 버튼이 눌리는지는 아무도 안 봤다. 그래서 여기서는 39개 패널의 컨트롤을 전부
# Playwright 의 실제 클릭 가능성 검사(trial click — 보이는가·움직이지 않는가·
# 그 점을 눌렀을 때 이 요소가 받는가)로 두드려 본다.
#
# 실측으로 잡은 것: 알림 선택·열 표시·스캔 대상 체크박스가 **13x13px** 이었다.
# 프로젝트는 이미 `@media (pointer: coarse)` 에서 44px 규칙을 세워 뒀는데, 새 표가
# Bootstrap 클래스 없이 맨 `<input type=checkbox>` 를 써서 그 규칙을 통째로
# 비껴갔다. 규칙이 있어도 **새 마크업이 그 규칙을 안 타면 소용이 없다** — 그래서
# 클래스가 아니라 화면에 그려진 실제 크기를 잰다.
TOUCH_MIN_PX = 20            # 체크박스·라디오의 최소 변 길이(현재 CSS 는 22px)
CONTROLS_PER_PANEL = 30      # 표가 길면 같은 모양이 반복된다 — 앞쪽만 봐도 충분하다

_CONTROL_SEL = ("button:not([disabled]), [data-action]:not([disabled]), "
                "select:not([disabled])")

# ⚠ 화살표 함수에는 `arguments` 가 없다(바깥 스코프의 것을 집어 undefined 와 비교하게
#   되어 **무엇과 비교해도 통과하는 가짜 가드**가 된다 — 이 테스트의 첫 판이 그랬다).
#   인자는 배열 하나로 받아 구조분해한다.
_BOXES_JS = """([name, minPx]) => {
  const root = document.getElementById('panel-' + name);
  if (!root) return [];
  const out = [];
  root.querySelectorAll('input[type=checkbox], input[type=radio]').forEach(el => {
    if (!el.offsetParent) return;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    if (Math.min(r.width, r.height) < minPx)
      out.push(`${el.id || el.dataset.action || el.getAttribute('aria-label') || 'checkbox'}`
               + ` ${Math.round(r.width)}x${Math.round(r.height)}px`);
  });
  return out;
}"""


def _phone_page(pw, live, width, height):  # noqa: F811
    """폰으로 연 상태를 만든다 — 터치 기기여야 `pointer: coarse` 규칙이 걸린다."""
    browser = _launch(pw)
    ctx = browser.new_context(viewport={"width": width, "height": height},
                             is_mobile=True, has_touch=True)
    page = ctx.new_page()
    page.goto(live["base"] + "/", wait_until="load")
    page.wait_for_timeout(2000)
    # 실시간 갱신을 멈춘다. 안 멈추면 목록이 다시 그려지는 순간 요소가 떨어져 나가
    # '눌리지 않음' 으로 보인다(실측: 그것만으로 허위 지적 42건).
    page.evaluate("() => { if (typeof consoleToggleLive === 'function') consoleToggleLive(); }")
    page.wait_for_timeout(500)
    return browser, page


@pytest.mark.skipif(sync_playwright is None, reason="playwright 미설치")
def test_controls_are_clickable_on_phone(live):  # noqa: F811
    width, height = 390, 750
    findings = []
    with sync_playwright() as pw:
        browser, page = _phone_page(pw, live, width, height)
        try:
            names = page.eval_on_selector_all(
                ".sidebar-link[data-panel]", "els => els.map(e => e.dataset.panel)")
            for name in list(dict.fromkeys(names)):
                page.evaluate("n => showPanel(n)", name)
                page.wait_for_timeout(PANEL_SETTLE_MS)
                controls = page.locator(f"#panel-{name} >> {_CONTROL_SEL}")
                for i in range(min(controls.count(), CONTROLS_PER_PANEL)):
                    el = controls.nth(i)
                    try:
                        if not el.is_visible():
                            continue
                        box = el.bounding_box()
                        if not box or box["width"] < 1 or box["height"] < 1:
                            continue
                        el.click(trial=True, timeout=1000)
                    except PWError:
                        try:                      # 다시 그려진 것뿐일 수 있다 — 한 번 더
                            el.click(trial=True, timeout=1500)
                        except PWError as again:
                            label = ""
                            try:
                                label = (el.get_attribute("data-action")
                                         or (el.inner_text() or "")[:24] or "").strip()
                            except PWError:
                                pass
                            findings.append(f"{name}: {label!r} 를 누를 수 없음"
                                            f" — {str(again).splitlines()[0][:80]}")
        finally:
            browser.close()
    assert findings == [], (
        f"[{width}x{height}] 폰에서 눌리지 않는 컨트롤:\n  " + "\n  ".join(findings))


@pytest.mark.skipif(sync_playwright is None, reason="playwright 미설치")
def test_touch_targets_are_big_enough(live):  # noqa: F811
    findings = []
    with sync_playwright() as pw:
        browser, page = _phone_page(pw, live, 390, 750)
        try:
            names = page.eval_on_selector_all(
                ".sidebar-link[data-panel]", "els => els.map(e => e.dataset.panel)")
            for name in list(dict.fromkeys(names)):
                page.evaluate("n => showPanel(n)", name)
                page.wait_for_timeout(PANEL_SETTLE_MS)
                for small in page.evaluate(_BOXES_JS, [name, TOUCH_MIN_PX]):
                    findings.append(f"{name}: {small}")
        finally:
            browser.close()
    assert findings == [], (
        f"폰에서 {TOUCH_MIN_PX}px 보다 작은 선택 컨트롤:\n  " + "\n  ".join(findings))


# ---------------------------------------------------------------- #
#  실시간 갱신이 화면의 숫자를 깨뜨리지 않는가
# ---------------------------------------------------------------- #
#
# MITRE 매트릭스 칸은 처음엔 서버가 '관측 57건' 으로 그리고, 그 뒤로는 소켓 이벤트가
# 1씩 올린다. 그 올리는 코드가 화면 글자를 `parseInt` 로 되읽었다 —
# `parseInt('관측 57건')` 은 **NaN** 이고 NaN+1 도 NaN 이라, 칸에 'NaN' 이 찍히고
# 색(hit-low/med/high)까지 함께 틀어졌다. 포트폴리오 스크린샷을 찍다가 발견했다.
#
# 이 계열은 "표시용 글자를 다시 숫자로 읽는" 실수라서, 한 번 나면 또 난다.
# 그래서 **화면에 NaN·undefined·[object Object] 가 찍히지 않는지**를 본다.
_BROKEN_TEXT = ("NaN", "undefined", "[object Object]", "Infinity")

# 서버가 그려 둔 칸에 소켓 갱신이 한 번 들어오는 상황을 **그대로** 만든다.
# 데모 알림이 우연히 그 칸을 때려 주기를 기다리면 아무것도 검사하지 않는 가드가
# 된다(첫 판이 그랬다 — 버그를 되살려도 통과했다).
_FIRE_HIT_JS = """([count]) => {
  const cell = document.querySelector('#panel-mitre .mitre-technique[data-technique]');
  if (!cell) return {error: '매트릭스 칸이 없다'};
  cell.dataset.count = String(count);
  let cnt = cell.querySelector('.tech-count');
  if (!cnt) { cnt = document.createElement('div'); cnt.className = 'tech-count'; cell.appendChild(cnt); }
  cnt.textContent = `관측 ${count}건`;          // 서버가 처음 그리는 형식
  const handlers = (typeof socket !== 'undefined' && socket.listeners)
    ? socket.listeners('mitre_hit') : [];
  if (!handlers.length) return {error: 'mitre_hit 핸들러가 없다'};
  handlers.forEach(fn => fn({tactic_id: cell.dataset.tactic, technique_id: cell.dataset.technique}));
  return {text: (cell.querySelector('.tech-count') || {}).textContent,
          klass: cell.className, kpi: (document.getElementById('kpi-mitre') || {}).textContent};
}"""


@pytest.mark.skipif(sync_playwright is None, reason="playwright 미설치")
def test_live_updates_do_not_print_broken_numbers(live):  # noqa: F811
    findings = []
    with sync_playwright() as pw:
        browser = _launch(pw)
        try:
            page = browser.new_page(viewport={"width": 1400, "height": 900})
            page.goto(live["base"] + "/", wait_until="load")
            page.wait_for_timeout(1500)
            page.evaluate("n => showPanel(n)", "mitre")
            page.wait_for_timeout(2000)

            result = page.evaluate(_FIRE_HIT_JS, [57])
            assert "error" not in result, result["error"]
            if result["text"] != "관측 58건":
                findings.append(f"소켓 갱신 뒤 칸 표기가 '관측 58건' 이 아니라 {result['text']!r}"
                                " — 표시용 글자를 다시 숫자로 읽었을 때 나는 증상")
            if "hit-high" not in result["klass"]:
                findings.append(f"58건인데 색이 hit-high 가 아님: {result['klass']!r}")

            # 화면 어디에도 깨진 값이 찍히지 않아야 한다
            for name in ("mitre", "overview"):
                page.evaluate("n => showPanel(n)", name)
                page.wait_for_timeout(4000)
                text = page.evaluate(
                    "n => (document.getElementById('panel-' + n) || {}).innerText || ''", name)
                for bad in _BROKEN_TEXT:
                    if bad in text:
                        line = next((ln.strip() for ln in text.splitlines() if bad in ln), bad)
                        findings.append(f"{name} 패널에 '{bad}' 가 표시됨 — {line[:60]!r}")
            odd = page.evaluate("""() => [...document.querySelectorAll('#panel-mitre .tech-count')]
                .map(e => e.textContent.trim())
                .filter(t => !/^관측 [0-9,]+건$/.test(t)).slice(0, 5)""")
            if odd:
                findings.append(f"매트릭스 칸 표기가 어긋남: {odd}")
        finally:
            browser.close()
    assert findings == [], "실시간 갱신이 화면 숫자를 깨뜨림:\n  " + "\n  ".join(findings)
