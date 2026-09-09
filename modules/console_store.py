"""Bounded, parameterized investigation queries over AlertStore's WAL reader.

No writes or new database. The archive union remains the source of truth.
"""
from datetime import datetime, timedelta
from concurrent.futures import Future
from threading import Lock

from modules.alert_dedup import extract_rule_id
from modules.provenance import sql_provenance
from modules.telemetry import telemetry

PROVENANCE_SQL = 'soc_provenance(description, details, origin, timestamp, src_ip, dst_ip)'
ORDER_SQL = {
    'priority': "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, id DESC",
    'newest': 'id DESC', 'oldest': 'id ASC', 'confidence': "CAST(json_extract(CASE WHEN json_valid(details) THEN details ELSE '{}' END, '$.confidence') AS REAL) DESC, id DESC",
}


class CoalescedReads:
    """Share overlapping identical reads, without retaining stale results.

    Per application, bounded to 16 in-flight keys. Exceptions reach every waiter;
    completed entries are removed, so the next request reads current evidence.
    """

    def __init__(self):
        self._lock = Lock()
        self._pending = {}

    def run(self, key, produce):
        with self._lock:
            future = self._pending.get(key)
            owner = future is None
            if owner and len(self._pending) < 16:
                future = self._pending[key] = Future()
        if future is None:
            return produce()
        if not owner:
            return future.result()
        try:
            result = produce()
            future.set_result(result)
            return result
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                del self._pending[key]


def search(reader, source, columns, row_to_dict, *, query='', severity='', status='',
           origin='', hours=24, limit=50, offset=0, order='priority', include_stats=False,
           scope='all', source_name='', minimum_confidence=0, rule=''):
    reader.create_function('soc_provenance', 6, sql_provenance, deterministic=True)
    where, params = [], []
    if hours:
        where.append('timestamp >= ?')
        params.append((datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S'))
    for key, value in [('severity', severity), ('status', status)]:
        if value:
            where.append(f'{key} = ?')
            params.append(value)
    if origin:
        where.append(PROVENANCE_SQL + ' = ?')
        params.append(origin)
    if source_name:
        where.append("COALESCE(json_extract(CASE WHEN json_valid(details) THEN details ELSE '{}' END, '$.source'), json_extract(CASE WHEN json_valid(details) THEN details ELSE '{}' END, '$.siem_source'), json_extract(CASE WHEN json_valid(details) THEN details ELSE '{}' END, '$.sensor')) = ?")
        params.append(source_name)
    if minimum_confidence:
        where.append("CAST(json_extract(CASE WHEN json_valid(details) THEN details ELSE '{}' END, '$.confidence') AS REAL) >= ?")
        params.append(minimum_confidence / 100)
    if rule:
        reader.create_function('soc_rule', 1, _sql_rule, deterministic=True)
        where.append('soc_rule(details) = ?')
        params.append(rule)
    if query:
        # LIKE metacharacters are literal user input; no SQL or wildcard injection.
        value = '%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        parts = [f"COALESCE({col}, '') LIKE ? ESCAPE '\\'" for col in
                 ['description', 'src_ip', 'dst_ip', 'threat_type', 'details', 'assignee']]
        params.extend([value] * len(parts))
        if query.lstrip('#').isdigit() and int(query.lstrip('#')) <= 9223372036854775807:
            parts.append('id = ?')
            params.append(int(query.lstrip('#')))
        # Technique mappings may be derived from the threat type, not stored in details.
        if query.upper().startswith('T'):
            from modules.mitre_attack import THREAT_MAPPING
            mapped = [kind for kind, pairs in THREAT_MAPPING.items()
                      if any(tech.upper() == query.upper() for _, tech in pairs)]
            if mapped:
                parts.append('threat_type IN (' + ','.join('?' for _ in mapped) + ')')
                params.extend(mapped)
        where.append('(' + ' OR '.join(parts) + ')')
    clause = ' WHERE ' + ' AND '.join(where) if where else ''
    archived = 'archived' if scope == 'all' else str(int(scope == 'archive'))
    with telemetry.timed('console.search'):
        total = reader.execute(f'SELECT COUNT(*) FROM {source}{clause}', params).fetchone()[0]
        rows = reader.execute(f'SELECT {columns}, {archived} FROM {source}{clause} '
                              f'ORDER BY {ORDER_SQL.get(order, ORDER_SQL["priority"])} LIMIT ? OFFSET ?',
                              params + [limit, offset]).fetchall()
        # AlertStore's decoder already applies server-derived provenance.
        result = {'alerts': [row_to_dict(row) for row in rows], 'total': total,
                  'limit': limit, 'offset': offset, 'hours': hours, 'scope': scope}
        if include_stats:
            counts = reader.execute(
                f'SELECT severity, status, {PROVENANCE_SQL}, COUNT(*) FROM {source}{clause} '
                'GROUP BY 1, 2, 3', params).fetchall()
            result['counts'] = [dict(zip(('severity', 'status', 'provenance', 'count'), r)) for r in counts]
            timeline = reader.execute(
                f'SELECT substr(timestamp, 1, 13), severity, COUNT(*) FROM {source}{clause} '
                'GROUP BY 1, 2 ORDER BY 1', params).fetchall()
            result['timeline'] = [dict(zip(('hour', 'severity', 'count'), r)) for r in timeline]
    return result


def _sql_rule(details):
    import json
    try:
        value = json.loads(details or '{}')
        return str(extract_rule_id(value if isinstance(value, dict) else {}))
    except (ValueError, TypeError):
        return ''
