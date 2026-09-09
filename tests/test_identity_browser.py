"""Real authenticated browser boundaries, against isolated services and data."""
import pytest

from modules.alert_store import AlertStore
from modules.identity import IdentityStore
from scripts.loadtest import _free_port, start_server, stop_server
from tests.test_browser_sweep import _launch, sync_playwright
from tests.test_console import save
from tests.test_console_browser import until

pytestmark = [pytest.mark.live, pytest.mark.browser,
              pytest.mark.skipif(sync_playwright is None, reason='playwright unavailable')]
PASSWORD = 'Isolated-Browser-Password-42!'


@pytest.fixture(scope='module')
def managed_live(tmp_path_factory):
    work = tmp_path_factory.mktemp('managed-browser')
    (work/'data').mkdir()
    (work/'watch').mkdir()
    proc, base = start_server(str(work), _free_port(), {'username':'owner','password':PASSWORD})
    identities = IdentityStore(str(work/'data'/'users.db'))
    for role in ('viewer','analyst'):
        identities.create(role, PASSWORD, role, actor='browser-fixture', reason='Isolated test')
    store = AlertStore(str(work/'data'/'alerts.db'))
    save(store, id=990001, severity='CRITICAL', origin='demo', details={'demo':True,'hostname':'role-test-host'})
    store.close()
    try:
        yield {'base':base, 'work':work, 'identities':identities}
    finally:
        identities.close()
        stop_server(proc)


@pytest.fixture
def role_browser(managed_live):
    findings = []
    with sync_playwright() as pw:
        browser = _launch(pw)
        def new_page(username):
            page = browser.new_page(base_url=managed_live['base'], viewport={'width':1920,'height':1080})
            page.on('pageerror', lambda error: findings.append(str(error)))
            page.on('console', lambda msg: findings.append(msg.text) if msg.type == 'error' else None)
            page.on('response', lambda response: findings.append(f'HTTP {response.status} {response.url}') if response.status >= 400 else None)
            page.on('requestfailed', lambda request: findings.append('Failed '+request.url) if request.failure != 'net::ERR_ABORTED' else None)
            page.goto(managed_live['base']+'/login')
            page.locator('#username').fill(username)
            page.locator('#password').fill(PASSWORD)
            page.locator('button[type=submit]').click()
            page.wait_for_load_state('load')
            page.wait_for_selector('.console-global-search')
            until(page, 'window.socket?.connected')
            return page
        yield new_page
        browser.close()
    assert findings == [], '\n'.join(findings)


def test_viewer_reads_evidence_and_cannot_use_mutation_controls(role_browser):
    page = role_browser('viewer')
    assert page.request.get('/api/whoami').json()['role'] == 'viewer'
    assert 'viewer' in page.locator('#access-context').inner_text()
    page.evaluate("consoleOpenInvestigation(990001)")
    page.wait_for_selector('#investigation-meta .provenance-demo')
    drawer = page.locator('#investigation-drawer')
    assert 'role-test-host' in drawer.inner_text()
    assert drawer.get_by_role('button', name='Acknowledge', exact=True).is_disabled()
    drawer.get_by_role('button', name='Analyst copilot', exact=True).click()
    assert drawer.get_by_role('button', name='Summarize evidence', exact=True).is_disabled()
    page.keyboard.press('Escape')
    page.evaluate("showPanel('soar')")
    until(page, "document.querySelector('[data-action=soarManualBlock]') !== null")
    assert page.locator('[data-action=soarManualBlock]').is_disabled()
    page.evaluate("showPanel('access')")
    until(page, "document.getElementById('access-status').textContent.includes('MANAGED')")
    assert page.locator('#access-create').is_disabled()
    assert page.locator('#access-users').get_by_role('button').count() == 0
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), page.evaluate("() => [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > innerWidth+1).map(e => [e.id,e.className,e.getBoundingClientRect().right])")


def test_admin_creates_user_and_revokes_existing_socket(role_browser, managed_live):
    admin = role_browser('owner')
    admin.evaluate("showPanel('access')")
    until(admin, "!document.getElementById('access-create').disabled")
    admin.locator('#access-create').click()
    assert admin.locator('#access-dialog').evaluate('(el) => el.contains(document.activeElement)')
    admin.locator('#access-username').fill('browser-created')
    admin.locator('#access-new-role').select_option('viewer')
    admin.locator('#access-new-password').fill(PASSWORD)
    admin.locator('#access-reason').fill('Browser regression account creation')
    admin.locator('#access-confirm-password').fill(PASSWORD)
    admin.locator('#access-submit').click()
    until(admin, "!document.getElementById('access-dialog').open")
    user = role_browser('browser-created')
    row = admin.locator('#access-users tr').filter(has_text='browser-created')
    row.get_by_role('button', name='Revoke sessions').click()
    admin.locator('#access-reason').fill('Browser regression session revocation')
    admin.locator('#access-confirm-password').fill(PASSWORD)
    admin.locator('#access-submit').click()
    until(admin, "!document.getElementById('access-dialog').open")
    until(user, '!socket.connected')
    # Navigate to login before refresh timers request protected telemetry.
    user.goto(managed_live['base']+'/login')
    assert user.locator('#username').is_visible()
    events = admin.request.get('/api/identity/audit').json()['events']
    assert any(event['target'] == 'browser-created' and event['action'] == 'USER_CHANGE' for event in events)
    assert 'Browser regression session revocation' in admin.locator('#access-audit').inner_text()


def test_analyst_ack_and_self_password_change(role_browser, managed_live):
    page = role_browser('analyst')
    page.evaluate('consoleOpenInvestigation(990001)')
    page.wait_for_selector('#investigation-meta .provenance-demo')
    page.get_by_role('button', name='Acknowledge', exact=True).click()
    page.locator('#analyst-action-reason').fill('Role authorized analyst evidence review')
    page.locator('#analyst-action-submit').click()
    until(page, "!document.getElementById('analyst-action-dialog').open")
    assert page.request.get('/api/console/alerts/990001').json()['alert']['status'] == 'ACK'
    page.keyboard.press('Escape')
    page.evaluate("showPanel('access')")
    until(page, "!document.getElementById('access-password-section').hidden")
    page.locator('#access-password-section summary').click()
    page.locator('#access-own-current').fill(PASSWORD)
    page.locator('#access-own-new').fill(PASSWORD+'new')
    page.get_by_role('button', name='Change password and sign out').click()
    page.wait_for_selector('#username')
    page.locator('#username').fill('analyst')
    page.locator('#password').fill(PASSWORD+'new')
    page.locator('button[type=submit]').click()
    page.wait_for_selector('.console-global-search')
    assert page.request.get('/api/whoami').json()['role'] == 'analyst'
