"""Analyst console invariants: exact evidence, conservative provenance, safe previews.

Stores are isolated under tmp_path. No app bootstrap, sensors, API calls or response
execution is needed to validate these contracts.
"""
import copy
import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from flask import Flask

from api.routes import api_bp
from modules.alert_store import AlertStore
from modules.audit_log import AuditLog
from modules.block_decision import BlockDecisionLog, evaluate_gates
from modules.console import alert_context, detection_quality, suppression_preview
from modules.correlation import build_campaigns
from modules.provenance import provenance
from modules.threat_detector import Alert, ThreatDetector


@pytest.fixture
def store(tmp_path):
    value = AlertStore(str(tmp_path / 'alerts.db'))
    yield value
    value.close()


def save(store, *, id=1, severity='HIGH', origin='real', details=None, age=0, description='Observed event'):
    alert = Alert('PORT_SCAN', severity, '8.8.4.4', '10.0.1.7', description, details)
    alert.id, alert.origin = id, origin
    alert.timestamp = (datetime.now() - timedelta(hours=age)).strftime('%Y-%m-%d %H:%M:%S')
    store.save(alert)
    return alert


@pytest.fixture
def app(store, tmp_path):
    app = Flask(__name__)
    app.config.update(SECRET_KEY='console-test-only', TESTING=True)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.threat_detector = SimpleNamespace(store=store)
    app.incidents = SimpleNamespace(snapshot=lambda: {})
    app.ai_analyst = SimpleNamespace(get_history=lambda limit: [], is_available=lambda: False)
    app.audit = AuditLog(str(tmp_path / 'audit.db'))
    app.block_decisions = BlockDecisionLog(str(tmp_path / 'decisions.db'))
    app.watchlist = SimpleNamespace(list_all=lambda: ([{'type':'ip','value':'8.8.4.4'}], {}))
    yield app
    app.audit.close()
    app.block_decisions.close()


@pytest.mark.parametrize('origin,details,expected', [
    ('real', {'demo':True}, 'DEMO'), ('demo', {}, 'DEMO'),
    ('legacy', {}, 'UNAVAILABLE'), ('', {}, 'UNAVAILABLE'),
    ('real', {'simulated':True}, 'SIMULATED'),
    ('real', {'source_mode':'experimental'}, 'EXPERIMENTAL'),
    ('real', {'source':'purple_team'}, 'SIMULATED'), ('real', {}, 'REAL'),
])
def test_provenance_is_explicit_and_conservative(origin, details, expected):
    record = {'origin':origin, 'details':details, 'description':'Observed event'}
    original = copy.deepcopy(record)
    assert provenance(record)['state'] == expected
    assert record == original


def test_reserved_test_address_cannot_look_like_real_evidence():
    assert provenance({'origin':'real','src_ip':'203.0.113.7'})['state'] == 'SYNTHETIC'


def test_search_preserves_archive_and_literal_query(store):
    save(store, id=1, description='percent%_ literal', age=48)
    save(store, id=2, description='unrelated')
    store.archive_older_than(1)
    result = store.console_search(query='%_', hours=0)
    assert result['total'] == 1
    assert result['alerts'][0]['id'] == 1 and result['alerts'][0]['archived']
    assert store.get_alert(1)['archived']
    assert not store.update_status(1, 'ACK')
    assert store.console_search(query="' OR 1=1 --", hours=0)['total'] == 0
    assert store.console_search(query='9' * 150, hours=0)['total'] == 0
    assert store.console_search(scope='live', hours=0)['total'] == 1
    assert store.console_search(scope='archive', hours=0)['total'] == 1


def test_exact_id_time_filters_counts_and_provenance(store):
    save(store, id=1, details={'demo': True}, severity='CRITICAL')
    save(store, id=11, age=30)
    result = store.console_search(query='#1', include_stats=True)
    assert result['total'] == 1
    assert result['counts'] == [{'severity':'CRITICAL','status':'OPEN','provenance':'DEMO','count':1}]
    assert sum(x['count'] for x in result['timeline']) == 1
    assert store.console_search(origin='REAL')['total'] == 0
    assert store.console_search(hours=48, origin='REAL')['total'] == 1


def test_rule_source_and_confidence_filter_use_actual_evidence(store):
    save(store, id=1, details={'rule_id':'sigma-1','siem_source':'web','confidence':.95})
    save(store, id=2, details={'rule_id':'sigma-2','source':'web','confidence':.5})
    result = store.console_search(rule='sigma-1', source_name='web', minimum_confidence=90)
    assert [a['id'] for a in result['alerts']] == [1]
    assert store.console_search(rule='missing')['total'] == 0


@pytest.mark.parametrize('query', ['hours=nan','hours=-1','hours=inf','limit=201','offset=-1',
                                   'severity=URGENT','status=BLOCKED','origin=fake','scope=other',
                                   'order=id%20DESC%3B','confidence=101','q=' + 'x'*201])
def test_filter_validation(app, query):
    assert app.test_client().get('/api/console/alerts?' + query).status_code == 400


def test_entity_search_groups_real_evidence(app, store):
    save(store)
    result = app.test_client().get('/api/console/entities?q=8.8.4.4').get_json()
    assert [g['type'] for g in result['groups']] == ['Alerts','Incidents','IOCs']
    assert result['total_alerts'] == 1
    assert result['groups'][2]['items'][0]['value'] == '8.8.4.4'
    assert result['unavailable']


def test_detail_uses_exact_links_and_never_invents_transition_times(app, store):
    save(store, id=1)
    save(store, id=11)
    app.audit.record('analyst', 'ALERT_ACK', '알림 #1', 'Reviewed')
    app.audit.record('analyst', 'ALERT_CLOSE', '알림 #11', 'Different alert')
    app.incidents = SimpleNamespace(snapshot=lambda: {
        1:{'id':1,'title':'case','status':'OPEN','alert_ids':[1], 'timeline':[]},
        2:{'id':2,'title':'other','status':'OPEN','alert_ids':[11], 'timeline':[]}})
    context = alert_context(app, 1)
    assert [i['id'] for i in context['incidents']] == [1]
    assert [e['action'] for e in context['audit']] == ['ALERT_ACK']
    assert {e['stage'] for e in context['timeline']} == {'DETECTED','ANALYST ACTION'}
    assert context['decisions'] == []
    assert app.test_client().get('/api/console/alerts/9999').status_code == 404


@pytest.mark.parametrize('alert_id', [2 ** 63, 10 ** 100])
def test_out_of_range_alert_id_is_not_a_server_error(app, alert_id):
    client = app.test_client()
    assert client.get(f'/api/console/alerts/{alert_id}').status_code == 404
    assert client.post('/api/console/copilot', json={'alert_id':alert_id}).status_code == 404


def test_quality_uses_analyst_denominator_and_marks_sampling(store):
    for i in range(1,6):
        save(store, id=i, details={'rule_id':'noisy','confidence':.8})
    store.set_verdict(1, 'TRUE_POSITIVE', 'analyst', 'Confirmed', '2026-09-09 10:00:00')
    store.set_verdict(2, 'FALSE_POSITIVE', 'analyst', 'Benign', '2026-09-09 10:00:00')
    records = store.console_search()['alerts']
    quality = detection_quality(records, 20)
    row = quality['rules'][0]
    assert row['fp_rate'] == 50 and row['unreviewed'] == 3
    assert row['confidence'] == [0,0,0,0,5]
    assert quality['truncated'] and quality['sample_size'] == 5
    assert detection_quality([records[0]], 1)['rules'][0]['fp_rate'] is None
    assert detection_quality([], 0)['rules'] == []


def test_preview_exempts_critical_and_never_mutates_evidence(app, store):
    save(store, id=1, severity='CRITICAL', details={'rule_id':'rule'})
    save(store, id=2, details={'rule_id':'rule'})
    records = store.console_search()['alerts']
    snapshot = copy.deepcopy(records)
    preview = suppression_preview(records, 'rule')
    assert preview['would_suppress'] == 1 and preview['critical_exempt'] == 1
    assert preview['mode'] == 'SIMULATED' and preview['writes'] is False
    assert records == snapshot
    result = app.test_client().post('/api/console/suppression-preview', json={'rule':'rule'})
    assert result.status_code == 200 and store.console_search()['alerts'] == snapshot
    assert app.audit.search(action='SUPPRESSION_PREVIEW')[1] == 1
    assert app.test_client().post('/api/console/suppression-preview', json={}).status_code == 400


def test_copilot_unavailable_returns_evidence_not_random_mock(app, store):
    save(store)
    c = app.test_client()
    data = c.post('/api/console/copilot', json={'alert_id':1}).get_json()
    assert data['generated'] is False and data['mode'] == 'EVIDENCE SUMMARY'
    assert data['inferences'] == [] and 'alert:1' in data['facts'][0]
    assert any('없' in item for item in data['unknowns'])
    assert app.audit.search(action='COPILOT_BRIEF')[1] == 1
    assert c.post('/api/console/copilot', json={'alert_id':True}).status_code == 400
    assert c.post('/api/console/copilot', json={'alert_id':1,'intent':'Block IP'}).status_code == 400


def test_model_cannot_replace_facts_or_erase_unknowns(app, store):
    save(store)
    app.ai_analyst.is_available = lambda: True
    app.ai_analyst.generate_text = lambda *a, **k: json.dumps({'facts':['Invented success'], 'inferences':['Unverified hypothesis'], 'recommendations':[], 'unknowns':[]})
    data = app.test_client().post('/api/console/copilot', json={'alert_id':1}).get_json()
    assert data['generated'] and 'Invented success' not in str(data['facts'])
    assert data['unknowns'] and data['inferences'] == ['Unverified hypothesis']
    app.ai_analyst.generate_text = lambda *a, **k: 'not valid JSON'
    assert not app.test_client().post('/api/console/copilot', json={'alert_id':1}).get_json()['generated']


def test_campaigns_never_combine_demo_with_real(store):
    for i in range(1,5):
        save(store, id=i, origin='real' if i < 3 else 'demo')
    campaigns = build_campaigns(store.since())
    assert len(campaigns) == 2
    assert {c['provenance']['state'] for c in campaigns} == {'REAL','DEMO'}
    assert sorted(c['alert_count'] for c in campaigns) == [2,2]


def test_durable_status_outside_memory_and_failed_writes(tmp_path, monkeypatch):
    detector = ThreatDetector(SimpleNamespace(emit=lambda *a, **k: None), config={}, store_path=str(tmp_path / 'durable.db'))
    try:
        record = save(detector.store)
        assert detector.update_alert_status(record.id, 'ACK', note='Reviewed', assignee='Ada')
        assert detector.store.get_alert(record.id)['assignee'] == 'Ada'
        detector.alerts.append(record)
        monkeypatch.setattr(detector.store, 'update_status', lambda *a, **k: (_ for _ in ()).throw(OSError('Disk failure')))
        with pytest.raises(OSError):
            detector.update_alert_status(record.id, 'CLOSED')
        assert record.status == 'OPEN'  # memory did not claim the failed write succeeded
    finally:
        detector.store.close()


def test_replay_missing_signal_and_changed_verdict_are_pure(app):
    args = dict(playbook_enabled=True, auto_block=True, severity='CRITICAL',
                is_true_positive=True, confidence=98, min_confidence=95,
                evidence=['abuseipdb_90','snort_signature'], require_corroboration=True,
                is_demo=False, is_external=True)
    passed, gates = evaluate_gates(**args)
    log = app.block_decisions
    did = log.record(alert_id=1, src_ip='8.8.4.4', blocked=False, gates_passed=passed,
                     outcome='queued_for_approval', gates=gates,
                     signals={'confidence':98,'evidence':args['evidence']},
                     thresholds={'min_block_confidence':95,'require_corroboration':True,'auto_block':True})
    before = log.get(did)
    assert not log.replay(did)['gates_changed']  # approval hold is not gate failure
    result = log.replay(did, without_evidence='abuseipdb_90')
    assert not result['replayed']['gates_passed'] and result['gates_changed']
    assert not log.replay(did, is_true_positive=False)['replayed']['gates_passed']
    assert log.get(did) == before and log.stats()['total'] == 1
    assert log.for_alert(11) == [] and log.for_alert(1)[0]['id'] == did
    c = app.test_client()
    for query in ['min_confidence=nan','min_confidence=101','auto_block=garbage','without_evidence=missing']:
        assert c.get(f'/api/soar/decisions/{did}/replay?{query}').status_code == 400
