"""Evidence workflows in the classic shell; data is seeded only in a temporary demo server."""
import json
import time

import pytest

from tests.test_browser_sweep import _launch, sync_playwright
from tests.test_live_server import live  # noqa: F401
from tests.test_console import save
from modules.alert_store import AlertStore

pytestmark = [pytest.mark.live, pytest.mark.browser,
              pytest.mark.skipif(sync_playwright is None, reason='playwright unavailable')]


def until(page, expression):
    # Playwright's wait_for_function uses eval, which this app's CSP forbids.
    # Evaluate via the debugger protocol; do not weaken CSP or bypass it.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if page.evaluate('() => (' + expression + ')'):
            return
        page.wait_for_timeout(100)
    raise AssertionError('Browser condition not met: ' + expression)


@pytest.fixture
def console_page(live):  # noqa: F811
    store = AlertStore(str(live['workdir'] / 'data' / 'alerts.db'))
    seed = save(store, id=990001, severity='CRITICAL', origin='demo',
                description='Browser regression <img src=x onerror=alert(1)>',
                details={'demo':True, 'rule_id':'trace-browser-check','confidence':.97,
                         'hostname':'trace-test-host','process':'evidence-process'})
    save(store, id=990002, severity='HIGH', origin='demo', details={'demo':True})
    store.close()
    findings = []
    with sync_playwright() as pw:
        browser = _launch(pw)
        page = browser.new_page(viewport={'width':1920,'height':1080})
        page.on('pageerror', lambda error: findings.append(str(error)))
        page.on('response', lambda response: findings.append(f'HTTP {response.status} {response.url}') if response.status >= 400 else None)
        page.on('console', lambda msg: findings.append(msg.text) if msg.type == 'error' else None)
        page.goto(live['base'], wait_until='load')
        until(page, "document.getElementById('cc-open').textContent !== '—'")
        yield page, seed.to_dict(), live
        browser.close()
    assert findings == [], '\n'.join(findings)


def open_seed_queue(page):
    page.evaluate("showPanel('alerts')")
    page.locator('#queue-search').fill('#990001')
    page.locator('#queue-status').select_option('')
    page.locator('#queue-search').press('Enter')
    until(page, "document.querySelectorAll('#console-queue-rows [data-alert-id]').length === 1")
    return page.locator('#console-queue-rows tr[data-alert-id="990001"]')


def test_queue_to_evidence_copilot_and_durable_ack(console_page):
    page, _, server = console_page
    row = open_seed_queue(page)
    row.focus()
    row.press('Enter')
    drawer = page.locator('#investigation-drawer')
    assert drawer.evaluate('(el) => el.open')
    page.wait_for_selector('#investigation-meta .provenance-demo')
    assert drawer.locator('img').count() == 0  # raw source markup remains escaped
    assert 'trace-test-host' in drawer.inner_text()
    drawer.get_by_role('button', name='Analyst copilot', exact=True).click()
    assert 'FACTS' in drawer.inner_text() and 'INFERENCES' in drawer.inner_text()
    drawer.get_by_role('button', name='Summarize evidence', exact=True).click()
    until(page, "document.querySelector('#investigation-brief .brief-section') !== null")
    assert 'EVIDENCE SUMMARY' in drawer.inner_text()
    drawer.get_by_role('button', name='Acknowledge', exact=True).click()
    page.locator('#analyst-action-reason').fill('Reviewed recorded evidence in the isolated browser regression.')
    page.locator('#analyst-action-submit').click()
    until(page, "!document.getElementById('analyst-action-dialog').open")
    until(page, "document.getElementById('investigation-meta').textContent.includes('ACK')")
    result = page.request.get(server['base'] + '/api/console/alerts/990001').json()
    assert result['alert']['status'] == 'ACK'
    assert any(e['action'] == 'ALERT_ACK' for e in result['audit'])
    assert result['alert']['description'].startswith('Browser regression <img')
    page.keyboard.press('Escape')
    until(page, "document.activeElement?.dataset.alertId === '990001'")


def test_paused_stream_buffers_and_queue_row_stays_selected(console_page):
    page, seed, _ = console_page
    row = open_seed_queue(page)
    row.locator('input[type=checkbox]').check()
    page.evaluate("window.traceSelectedRow = document.querySelector('#console-queue-rows tr[data-alert-id]'); SOCRealtime.setPaused(true)")
    before = page.locator('#stat-total-alerts').inner_text()
    page.evaluate("a => socket.onevent({data:['new_alert',a]})", seed)
    assert page.locator('#stat-total-alerts').inner_text() == before
    assert 'PAUSED' in page.locator('#badge-status').inner_text()
    assert page.evaluate('SOCRealtime.pending') >= 1
    assert '+1' in page.locator('#console-pending').inner_text() or page.evaluate('SOCRealtime.pending') > 1
    page.evaluate('SOCRealtime.setPaused(false)')
    assert page.evaluate("window.traceSelectedRow === document.querySelector('#console-queue-rows tr[data-alert-id]')")
    assert row.locator('input[type=checkbox]').is_checked()
    assert '1 selected' in page.locator('#queue-selected').inner_text()
    assert page.locator('#queue-new-events').inner_text().startswith('+')


def test_command_palette_keyboard_entity_search_and_focus(console_page):
    page, _, _ = console_page
    trigger = page.locator('.console-global-search')
    trigger.focus()
    page.keyboard.press('Control+k')
    page.locator('#palette-input').fill('trace-test-host')
    result = page.locator('#palette-results button').filter(has_text='#990001')
    result.wait_for()
    assert 'DEMO' in result.inner_text()
    page.keyboard.press('ArrowDown')
    page.keyboard.press('Enter')
    page.wait_for_selector('#investigation-drawer[open]')
    page.keyboard.press('Escape')
    assert not page.locator('#investigation-drawer').evaluate('(el) => el.open')
    page.keyboard.press('Control+k')
    page.keyboard.press('Escape')
    assert not page.locator('#command-palette').evaluate('(el) => el.open')


def test_siem_timestamp_filter_and_field_query(console_page):
    page, _, _ = console_page
    # Await the real initial snapshot before injecting evidence: globe loading can
    # delay the HTTP response beyond a fixed sleep and overwrite our test stream.
    with page.expect_response('**/api/integrations/siem') as snapshot:
        page.evaluate("showPanel('siem')")
    snapshot.value.finished()
    until(page, "document.querySelector('#siem-sources-ok').textContent !== ''")
    page.evaluate("""() => {
      SOCRealtime.setPaused(true);
      // Resume to inject through actual registered Socket.IO handlers, then freeze.
      SOCRealtime.setPaused(false);
      socket.onevent({data:['siem_status',{stats:{},sources:[],events:[
        {timestamp:'09/Sep/2026 10:00:00',timestamp_epoch:Date.now()/1000-60,ip:'8.8.4.4',source:'web',request:'GET /a',status:403,severity:'HIGH',suspicious:true,provenance:{state:'DEMO'}},
        {timestamp:'09/Sep/2026 09:00:00',timestamp_epoch:Date.now()/1000-3600,ip:'8.8.4.4',source:'web',request:'GET /b',status:403,severity:'HIGH',suspicious:true,provenance:{state:'DEMO'}},
        {timestamp:'unknown',ip:'8.8.4.4',source:'web',request:'GET /c',status:403,severity:'HIGH',suspicious:true,provenance:{state:'DEMO'}}
      ]}]}); SOCRealtime.setPaused(true);
    }""")
    page.locator('#siem-timerange').select_option('5')
    page.locator('#siem-search').fill('src_ip=8.8.4.4 status=403')
    assert page.locator('#siem-result-count').inner_text() == '1'
    page.locator('#siem-search').press('Enter')
    until(page, "document.querySelector('#siem-history').options.length > 1")
    with page.expect_download() as info:
        page.get_by_role('button', name='Export evidence snapshot').click()
    data = json.loads(open(info.value.path()).read())
    assert len(data['events']) == 1 and data['minutes'] == 5
    assert data['events'][0]['provenance']['state'] == 'DEMO'


@pytest.mark.parametrize('width', [320, 390])
def test_mobile_critical_review_has_no_horizontal_overflow(console_page, width):
    page, _, _ = console_page
    page.set_viewport_size({'width':width,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    open_seed_queue(page).click(position={'x':95,'y':16})
    page.wait_for_selector('#investigation-meta .provenance-demo')
    assert page.locator('#investigation-drawer').evaluate('(el) => el.scrollWidth <= el.clientWidth')
    page.locator('#investigation-drawer').get_by_role('button', name='Acknowledge', exact=True).click()
    assert page.locator('#analyst-action-reason').is_visible()
    page.keyboard.press('Escape')


def test_pause_coalesces_snapshots_and_bounds_event_buffer(console_page):
    page, _, _ = console_page
    result = page.evaluate("""() => {
      SOCRealtime.setPaused(false);
      const receivers = {}, delivered = [];
      const fakeClient = {on(event, handler) { receivers[event] = handler; return this; }};
      SOCRealtime.attach(fakeClient);
      fakeClient.on('siem_status', value => delivered.push(['snapshot', value]));
      fakeClient.on('buffer_contract_test', value => delivered.push(['event', value]));
      SOCRealtime.setPaused(true);
      for (let i = 0; i < 5000; i++) receivers.siem_status(i);
      receivers.buffer_contract_test(1); receivers.buffer_contract_test(2);
      const snapshot = {pending:SOCRealtime.pending, retained:SOCRealtime.buffer.length};
      SOCRealtime.setPaused(false);
      snapshot.delivered = delivered.splice(0);
      SOCRealtime.setPaused(true);
      for (let i = 0; i < 750; i++) receivers.buffer_contract_test(i);
      const overflow = {pending:SOCRealtime.pending, retained:SOCRealtime.buffer.length,
                        omitted:SOCRealtime.omitted};
      SOCRealtime.setPaused(false);
      overflow.values = delivered.map(item => item[1]);
      return {snapshot,overflow,remaining:SOCRealtime.snapshots.size};
    }""")
    assert result['snapshot'] == {'pending':5002, 'retained':3,
                                  'delivered':[['snapshot',4999],['event',1],['event',2]]}
    assert result['overflow']['pending'] == 750
    assert result['overflow']['retained'] == 500
    assert result['overflow']['omitted'] == 250
    assert result['overflow']['values'] == list(range(250,750))
    assert result['remaining'] == 0


def test_queue_columns_resize_with_keyboard_and_preserve_selection(console_page):
    page, _, _ = console_page
    row = open_seed_queue(page)
    row.locator('input[type=checkbox]').check()
    handle = page.locator('#console-queue-table th.col-confidence .column-resize-handle')
    handle.focus()
    handle.press('ArrowRight')
    first = float(handle.get_attribute('aria-valuenow'))
    handle.press('ArrowRight')
    assert float(handle.get_attribute('aria-valuenow')) > first
    assert row.locator('input[type=checkbox]').is_checked()
    page.evaluate("showPanel('overview')")
    page.locator('#evidence-summary > summary').click()
    priority = page.locator('#console-priority tr[data-alert-id]').first
    alert_id = priority.get_attribute('data-alert-id')
    requests = []
    page.on('request', lambda request: requests.append(request.url)
            if request.url.endswith('/api/console/alerts/' + alert_id) else None)
    priority.focus()
    priority.press('Enter')
    page.wait_for_selector('#investigation-meta .provenance')
    assert len(requests) == 1  # one keyboard activation, one evidence request


def test_classic_shell_restores_live_wall_without_losing_evidence(console_page):
    page, _, _ = console_page
    assert page.title() == 'SOC 보안관제 대시보드'
    assert page.locator('#panel-overview h1').inner_text().startswith('AI 관제 센터')
    assert page.locator('#sgroup-head-siem').inner_text().startswith('SIEM · 수집/탐지')
    assert page.locator('#live-stream').evaluate('(el) => !!el.closest(".command-wall")')
    assert page.locator('#overview-map').evaluate('(el) => el.open')
    page.wait_for_selector('#attack-globe canvas')
    assert not page.locator('#evidence-summary').evaluate('(el) => el.open')
    page.locator('#overview-map > summary').click()
    assert not page.locator('#attack-globe').is_visible()
    assert page.locator('#live-stream').is_visible()
    page.locator('#evidence-summary > summary').click()
    assert page.locator('#console-priority [data-alert-id]').count() > 0
    assert page.locator('#console-priority .provenance-demo').count() > 0
    assert page.locator('form[action="/logout"]').get_attribute('method') == 'POST'
    assert page.locator('.sidebar-link[data-panel="access"]').count() == 1
    assert page.locator('.sidebar-link[data-panel="quality"]').count() == 1
