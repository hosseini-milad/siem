"""Unsupervised scoring and bounded evidence graphs for one observed IP."""
from collections import defaultdict
from datetime import timedelta
from math import sqrt
from statistics import median

from app.models.log import COLLECTION
from app.services.agent_ingestion import AGENT_LOGS
from app.services.web_access import RECORDS

MAX_ROWS_PER_SOURCE = 5000
MIN_BASELINE_WINDOWS = 8
SCORE_THRESHOLD = 3.5
DOMAINS = ('network', 'system', 'web')
SOURCES = {'network': COLLECTION, 'system': AGENT_LOGS, 'web': RECORDS}


def observed_events(database, address, start, end):
    specifications = {
        'network': (
            {'$or': [{'attributes.source_ip': address}, {'attributes.destination_ip': address}],
             'attributes.agent_id': {'$exists': False}, 'attributes.agent_payload': {'$exists': False}},
            {'attributes.source_ip': 1, 'attributes.destination_ip': 1, 'source': 1, 'level': 1},
        ),
        'system': (
            {'$or': [{'device_ip': address}, {'device_ip': {'$exists': False}, 'source_ip': address}]},
            {'system_id': 1, 'mac': 1, 'source_ip': 1, 'device_ip': 1, 'received_at': 1, 'agent_id': 1, 'event_id': 1, 'type': 1},
        ),
        'web': (
            {'source_ip': address},
            {'service': 1, 'status': 1, 'route': 1, 'request_id': 1},
        ),
    }
    events, coverage = [], {}
    for domain, (query, projection) in specifications.items():
        match = {**query, 'timestamp': {'$gte': start, '$lt': end}}
        cursor = database[SOURCES[domain]].find(match, {**projection, 'timestamp': 1}).sort(
            [('timestamp', -1), ('_id', -1)]).limit(MAX_ROWS_PER_SOURCE + 1).max_time_ms(15000)
        with cursor:
            rows = list(cursor)
        coverage[domain] = {'rows': min(len(rows), MAX_ROWS_PER_SOURCE), 'truncated': len(rows) > MAX_ROWS_PER_SOURCE}
        events.extend(normalize_event(domain, row, address) for row in rows[:MAX_ROWS_PER_SOURCE])
    return events, coverage


def normalize_event(domain, row, address):
    if domain == 'network':
        attributes = row.get('attributes') or {}
        outbound = attributes.get('source_ip') == address
        peer = attributes.get('destination_ip' if outbound else 'source_ip')
        relation = 'network_destination' if outbound else 'network_origin'
        target = ('ip', str(peer)) if peer and peer != address else ('network_source', str(row.get('source') or 'unknown'))
        signal = row.get('level') in ('WARNING', 'ERROR', 'CRITICAL')
        summary = {'level': row.get('level'), 'direction': 'outbound' if outbound else 'inbound'}
    elif domain == 'system':
        mac = row.get('mac') or row.get('system_id')
        target = ('mac', str(mac)) if mac else ('agent', str(row.get('agent_id') or 'unknown'))
        relation = 'reported_ip_at_receipt' if row.get('device_ip') == address else 'connection_ip_at_receipt'
        signal = row.get('type') in (1, 2, '1', '2')
        summary = {'event_id': row.get('event_id'), 'level': row.get('type'), 'received_at': row.get('received_at')}
    else:
        target = ('web_service', str(row.get('service') or 'unknown'))
        relation = 'web_request'
        status = row.get('status')
        signal = isinstance(status, int) and status >= 400
        summary = {'status': status, 'route': row.get('route'), 'request_id': row.get('request_id')}
    return {'domain': domain, 'id': str(row['_id']), 'timestamp': row['timestamp'],
            'target': target, 'relation': relation, 'signal': signal, 'summary': summary}


def graph_features(events):
    features = dict.fromkeys((f'{domain}_{name}' for domain in DOMAINS
                             for name in ('events', 'distinct_edges', 'signals')), 0)
    edges = defaultdict(set)
    for event in events:
        domain = event['domain']
        features[f'{domain}_events'] += 1
        features[f'{domain}_signals'] += event['signal']
        edges[domain].add((event['relation'], event['target']))
    for domain, unique in edges.items():
        features[f'{domain}_distinct_edges'] = len(unique)
    features['active_domains'] = len(edges)
    return features


def evidence_graph(address, events):
    root = 'ip:' + address
    nodes = {root: {'id': root, 'kind': 'ip', 'label': address}}
    edges = {}
    evidence = []
    for domain in DOMAINS:
        candidates = sorted((event for event in events if event['domain'] == domain),
                            key=lambda event: (event['signal'], event['timestamp']), reverse=True)
        for event in candidates[:12]:
            kind, label = event['target']
            target = f'{kind}:{label}'
            nodes[target] = {'id': target, 'kind': kind, 'label': label}
            edge_key = (event['relation'], target)
            edge = edges.setdefault(edge_key, {'source': root, 'target': target,
                                               'relation': event['relation'], 'evidence': []})
            reference = f"{domain}:{event['id']}"
            edge['evidence'].append(reference)
            evidence.append({'ref': reference, 'id': event['id'], 'collection': SOURCES[domain],
                             'domain': domain, 'timestamp': event['timestamp'], **event['summary']})
    return {'nodes': list(nodes.values()), 'edges': list(edges.values()),
            'evidence': sorted(evidence, key=lambda row: row['timestamp']),
            'evidence_total': len(events), 'evidence_shown': len(evidence)}


def assess(database, address, end, baseline_hours, window_minutes):
    step = timedelta(minutes=window_minutes)
    start = end - step
    baseline_windows = baseline_hours * 60 // window_minutes
    baseline_start = start - step * baseline_windows
    events, coverage = observed_events(database, address, baseline_start, end)
    prior = defaultdict(list)
    current = []
    for event in events:
        if event['timestamp'] >= start:
            current.append(event)
        else:
            prior[(event['timestamp'] - baseline_start) // step].append(event)
    baseline = [graph_features(group) for group in prior.values()]
    features = graph_features(current)
    identities = sorted({event['target'][1] for event in events if event['target'][0] == 'mac'})
    result = {
        'ip': address, 'window_start': start, 'window_end': end, 'baseline_start': baseline_start,
        'active_baseline_windows': len(baseline), 'required_baseline_windows': MIN_BASELINE_WINDOWS,
        'scoring_window_minutes': window_minutes, 'coverage': coverage, 'observed_macs': identities,
        'score': None, 'threshold': SCORE_THRESHOLD, 'reasons': [],
        'features': features, 'graph': evidence_graph(address, current),
    }
    if any(source['truncated'] for source in coverage.values()):
        return {**result, 'state': 'volume_limit'}
    if len(identities) > 1:
        return {**result, 'state': 'ambiguous_identity'}
    if not current:
        return {**result, 'state': 'no_activity'}
    if len(baseline) < MIN_BASELINE_WINDOWS:
        return {**result, 'state': 'insufficient_baseline'}

    reasons = []
    for key, value in features.items():
        history = [row[key] for row in baseline]
        typical = median(history)
        deviation = median(abs(item - typical) for item in history)
        # Floor the scale to avoid treating tiny changes in static features as strong evidence.
        scale = max(1.4826 * deviation, sqrt(typical + 1))
        score = max(0, (value - typical) / scale)
        if score > 0:
            reasons.append({'feature': key, 'observed': value, 'baseline_median': typical, 'score': round(score, 3)})
    reasons.sort(key=lambda item: (-item['score'], item['feature']))
    score = reasons[0]['score'] if reasons else 0.0
    return {**result, 'state': 'anomalous' if score >= SCORE_THRESHOLD else 'within_baseline',
            'score': score, 'reasons': reasons[:5]}
