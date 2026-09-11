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
                         'text': 'DEMO 출력' if entry.get('model') == 'demo' else '모델 참고 분석',
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
    techniques = [{'tactic': tactic, 'technique': tech, 'basis': '위협 유형 매핑'}
                  for tactic, tech in THREAT_MAPPING.get(alert['threat_type'], [])]
    if details.get('mitre'):
        techniques.append({'technique': details['mitre'], 'basis': '탐지 필드 기록'})
    return {'alert': alert, 'related_alerts': related, 'incidents': incidents,
            'decisions': decisions, 'audit': audits, 'ai': ai, 'timeline': timeline,
            'techniques': techniques, 'evidence': details,
            'storage': '아카이브 / 읽기 전용' if alert['archived'] else '저장됨',
            'limits': ['관련 알림: 7일 내 같은 출처의 텍스트 개체 일치 최신 30건.',
                       'AI 이력은 현재 프로세스에 한정되며, 이력이 없다는 것이 부정 결과는 아니다.',
                       '보강·종결 시각은 추정하지 않는다. 전체 인시던트 이력은 인시던트 패널에 있다.']}


def evidence_brief(context):
    alert = context['alert']
    aid = alert['id']
    ref = f'alert:{aid}'
    facts = [f'[{ref}] {alert["timestamp"]} · {alert["severity"]} · {alert["threat_type"]}',
             f'[{ref}] 출발지 {alert.get("src_ip") or "미기록"} → {alert.get("dst_ip") or "목적지 미기록"}',
             f'[{ref}] 상태 {alert["status"]} · 분석가 판정 {alert.get("verdict") or "미검토"}.',
             f'[{ref}] 출처 {alert["provenance"]["state"]}: {alert["provenance"]["reason"]}']
    if alert.get('description'):
        facts.append(f'[{ref}] 탐지 설명: {alert["description"]}')
    for item in context['decisions']:
        facts.append(f'[decision:{item["id"]}] {item["ts"]}: {item.get("outcome_label") or item.get("outcome") or "결과 미기록"}.')
    unknowns = []
    if not context['ai']:
        unknowns.append('이 알림에 연결된 AI 트리아지 기록이 없습니다.')
    if not context['incidents']:
        unknowns.append('이 알림 ID 를 포함하는 인시던트가 없습니다.')
    if not context['decisions']:
        unknowns.append('이 알림에 연결된 차단 결정이 없어 대응 성공 여부를 알 수 없습니다.')
    unknowns.extend(['신뢰도는 탐지 점수이지 측정된 AI 정확도가 아닙니다.',
                     'ML 은 참고용이며 알림별 ML 결론을 가정하지 않습니다.'])
    return {'facts': facts, 'inferences': [],
            'recommendations': [f'[{ref}] 의 원본·정규화 증거를 검토하세요.',
                                '대응 전에 관련 이벤트를 비교하고 영향 자산을 교차 확인하세요.',
                                '근거를 남긴 분석가 판정을 기록하고, 영향이 큰 조치 전에는 대응 게이트를 검토하세요.'],
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
        days[(alert.get('timestamp') or '미상')[:10]][verdict_key] += 1
        details = alert.get('details') or {}
        sources[str(details.get('source') or details.get('siem_source') or details.get('sensor') or '소스 미기록')] += 1
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
            'dedup': dedup, 'definition': '분석가 FP / (분석가 TP + 분석가 FP). 미검토 건 제외 · 모델 정확도 아님.'}


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
            'explanation': '룰/유형 정확 일치와 출발지 접두 리터럴 일치. CRITICAL 알림은 면제. 룰을 만들지 않고 증거를 바꾸지 않습니다.'}


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
            campaign['provenance'] = {'state': state, 'reason': '모든 구성 알림이 같은 출처 분류를 공유합니다.'}
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
