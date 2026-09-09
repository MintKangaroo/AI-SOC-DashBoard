"""Evidence composition for the analyst console. No response actions live here."""
from collections import Counter, defaultdict
from datetime import datetime

from modules.alert_dedup import extract_rule_id
from modules.correlation import build_campaigns
from modules.mitre_attack import THREAT_MAPPING
from modules.provenance import annotate, provenance


def alert_context(app, alert_id):
    store = app.threat_detector.store
    alert = store.get_alert(alert_id)
    if alert is None:
        return None
    alert = annotate(alert)
    details = alert.get('details') or {}
    if not isinstance(details, dict):
        details = {}
    related = store.console_search(query=alert.get('src_ip') or str(alert_id),
                                   hours=168, limit=30, order='newest')['alerts']
    related = [a for a in related if a['id'] != alert_id
               and a['provenance']['state'] == alert['provenance']['state']]
    incidents = [i for i in app.incidents.snapshot().values() if alert_id in i.get('alert_ids', [])]
    decisions = app.block_decisions.for_alert(alert_id) if getattr(app, 'block_decisions', None) else []
    audits = app.audit.search(target=f'알림 #{alert_id}', limit=100)[0] if getattr(app, 'audit', None) else []
    ai_history = app.ai_analyst.get_history(1000) if getattr(app, 'ai_analyst', None) else []
    ai = [a for a in ai_history if a.get('type') == 'alert_analysis' and a.get('ref_id') == alert_id]
    # No transition timestamp is invented. Enrichment without a timestamp is evidence,
    # but it cannot be placed on a chronological timeline.
    timeline = [{'stage': 'DETECTED', 'timestamp': alert['timestamp'],
                 'text': alert.get('description'), 'reference': f'alert:{alert_id}'}]
    for entry in ai:
        timeline.append({'stage': 'AI TRIAGED', 'timestamp': entry.get('timestamp'),
                         'text': 'DEMO output' if entry.get('model') == 'demo' else 'Advisory model analysis',
                         'reference': f'alert:{alert_id}'})
    for decision in decisions:
        timeline.append({'stage': 'SOAR DECISION', 'timestamp': decision['ts'],
                         'text': decision.get('outcome_label') or decision.get('reason'),
                         'reference': f'decision:{decision["id"]}'})
    for event in audits:
        timeline.append({'stage': 'ANALYST ACTION', 'timestamp': event['ts'],
                         'text': f'{event["actor"]}: {event["action"]} · {event["detail"]}',
                         'reference': f'audit:{event["id"]}'})
    for incident in incidents:
        for event in incident.get('timeline', []):
            if event.get('kind') == 'alert' and f'알림 #{alert_id} ' in event.get('text', ''):
                timeline.append({'stage': 'INCIDENT', 'timestamp': event.get('ts'),
                                 'text': event.get('text'), 'reference': f'incident:{incident["id"]}'})
    timeline.sort(key=lambda item: item.get('timestamp') or '')
    techniques = [{'tactic': tactic, 'technique': tech, 'basis': 'Threat-type mapping'}
                  for tactic, tech in THREAT_MAPPING.get(alert['threat_type'], [])]
    if details.get('mitre'):
        techniques.append({'technique': details['mitre'], 'basis': 'Recorded detection field'})
    return {'alert': alert, 'related_alerts': related, 'incidents': incidents,
            'decisions': decisions, 'audit': audits, 'ai': ai, 'timeline': timeline,
            'techniques': techniques, 'evidence': details,
            'storage': 'ARCHIVED / READ ONLY' if alert['archived'] else 'STORED',
            'limits': ['Related alerts: latest 30 textual entity matches within 7 days, same provenance.',
                       'AI history is limited to the current process; missing history is not a negative result.',
                       'No timestamp is inferred for enrichment or closure. Full case history remains in Incidents.']}


def evidence_brief(context):
    alert = context['alert']
    aid = alert['id']
    ref = f'alert:{aid}'
    facts = [f'[{ref}] {alert["timestamp"]} · {alert["severity"]} · {alert["threat_type"]}',
             f'[{ref}] Source {alert.get("src_ip") or "not recorded"} → {alert.get("dst_ip") or "destination not recorded"}',
             f'[{ref}] Status {alert["status"]}; analyst verdict {alert.get("verdict", "UNREVIEWED")}.',
             f'[{ref}] Provenance {alert["provenance"]["state"]}: {alert["provenance"]["reason"]}']
    if alert.get('description'):
        facts.append(f'[{ref}] Recorded detection: {alert["description"]}')
    for item in context['decisions']:
        facts.append(f'[decision:{item["id"]}] {item["ts"]}: {item.get("outcome_label") or item.get("outcome") or "Outcome not recorded"}.')
    unknowns = []
    if not context['ai']:
        unknowns.append('No retained AI triage is linked to this alert.')
    if not context['incidents']:
        unknowns.append('No incident contains this alert ID.')
    if not context['decisions']:
        unknowns.append('No block decision is linked to this alert; response success is unknown.')
    unknowns.extend(['Confidence is a detection score, not measured AI accuracy.',
                     'ML is advisory; no per-alert ML conclusion is assumed.'])
    return {'facts': facts, 'inferences': [],
            'recommendations': [f'Review the raw and normalized evidence for [{ref}].',
                                'Compare related events and corroborate the affected asset before responding.',
                                'Record a reasoned analyst verdict; review response gates before any high-impact action.'],
            'unknowns': unknowns, 'generated': False, 'mode': 'EVIDENCE SUMMARY'}


def detection_quality(alerts, total, dedup=None):
    rules = defaultdict(lambda: {'total': 0, 'tp': 0, 'fp': 0, 'unreviewed': 0,
                                'confidence': [0] * 5, 'provenance': Counter()})
    days = defaultdict(lambda: {'tp': 0, 'fp': 0, 'unreviewed': 0})
    sources = Counter()
    for alert in alerts:
        key = str(extract_rule_id(alert.get('details') or {}) or alert['threat_type'])
        row = rules[key]
        row['total'] += 1
        verdict = alert.get('verdict')
        verdict_key = 'tp' if verdict == 'TRUE_POSITIVE' else 'fp' if verdict == 'FALSE_POSITIVE' else 'unreviewed'
        row[verdict_key] += 1
        days[(alert.get('timestamp') or 'Unknown')[:10]][verdict_key] += 1
        details = alert.get('details') or {}
        sources[str(details.get('source') or details.get('siem_source') or details.get('sensor') or 'Source unavailable')] += 1
        row['provenance'][provenance(alert)['state']] += 1
        confidence = (alert.get('details') or {}).get('confidence')
        if isinstance(confidence, (float, int)) and 0 <= confidence <= 1:
            row['confidence'][min(4, int(confidence * 5))] += 1
    output = []
    for rule, row in rules.items():
        reviewed = row['tp'] + row['fp']
        output.append({'rule': rule, **row, 'fp_rate': round(100 * row['fp'] / reviewed, 1) if reviewed else None})
    return {'rules': sorted(output, key=lambda row: row['total'], reverse=True),
            'trend': [{'date': date, **values,
                       'fp_rate': round(100 * values['fp'] / (values['fp'] + values['tp']), 1)
                       if values['fp'] + values['tp'] else None} for date, values in sorted(days.items())],
            'sources': [{'source': source, 'count': count} for source, count in sources.most_common(10)],
            'sample_size': len(alerts), 'total': total, 'truncated': total > len(alerts),
            'dedup': dedup, 'definition': 'Analyst FP / (analyst TP + analyst FP). Unreviewed records excluded; not model accuracy.'}


def suppression_preview(alerts, rule, source_prefix='', threat_type=''):
    matched, exempt = [], []
    for alert in alerts:
        if rule and str(extract_rule_id(alert.get('details') or {})) != rule:
            continue
        if source_prefix and not str(alert.get('src_ip') or '').startswith(source_prefix):
            continue
        if threat_type and alert.get('threat_type') != threat_type:
            continue
        (exempt if alert['severity'] == 'CRITICAL' else matched).append(alert['id'])
    return {'mode': 'SIMULATED', 'would_suppress': len(matched), 'critical_exempt': len(exempt),
            'alert_ids': matched[:100], 'examined': len(alerts), 'writes': False,
            'explanation': 'Exact rule/type and literal source-prefix match. CRITICAL alerts remain exempt. No rule is created and no evidence is changed.'}


def campaigns_for(alerts):
    # Synthetic and real evidence must never become one narrative because they
    # happen to share an IP. Unknown origin remains a separate group.
    groups = defaultdict(list)
    for alert in alerts:
        if alert.get('src_ip'):
            groups[provenance(alert)['state']].append(alert)
    campaigns = []
    for state, records in groups.items():
        for campaign in build_campaigns(records):
            campaign['provenance'] = {'state': state, 'reason': 'All member alerts share this classified provenance.'}
            campaigns.append(campaign)
    return sorted(campaigns, key=lambda item: (item['stage_count'], item['alert_count']), reverse=True)


def technique_observations(alerts):
    """Recorded mappings plus existing threat-type mappings, once per alert/technique."""
    import re
    result = defaultdict(lambda: {'count': 0, 'provenance': Counter()})
    for alert in alerts:
        techniques = {tech for _, tech in THREAT_MAPPING.get(alert['threat_type'], [])}
        details = alert.get('details') or {}
        for key in ('mitre', 'mitre_techniques', 'mitre_technique', 'technique_id'):
            techniques.update(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', str(details.get(key, ''))))
        for technique in techniques:
            result[technique]['count'] += 1
            result[technique]['provenance'][provenance(alert)['state']] += 1
    return dict(result)


def now_text():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
