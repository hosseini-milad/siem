from datetime import datetime, timedelta, timezone

from app.services import search


def overview(database, hours):
    end = datetime.now(timezone.utc)
    since = end - timedelta(hours=hours)
    stats = search.statistics(database, search.event_filter(start=since, end=end), 'hour')
    return {
        'since': since,
        'hours': hours,
        'open_alerts': database.siem_alerts.count_documents({'status': {'$in': ['open', 'acknowledged']}}),
        'active_incidents': database.siem_incidents.count_documents({'status': {'$ne': 'closed'}}),
        'enabled_rules': database.siem_rules.count_documents({'enabled': True}),
        'hourly_events': stats.pop('series'),
        **stats,
    }


DOMAINS = ('network', 'system', 'web')
SEVERITIES = ('critical', 'high', 'medium', 'low')
QUERY_TIMEOUT = 30_000
WEB_BATCHES = 'web_service_batches'


def time_series(collection, match, timestamp, interval, count=1):
    return collection.aggregate([
        {'$match': match},
        {'$group': {'_id': {'$dateTrunc': {'date': timestamp, 'unit': interval}},
                    'count': {'$sum': count}}},
    ], maxTimeMS=QUERY_TIMEOUT)


def operational_overview(database, hours):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    interval = 'hour' if hours <= 24 else 'day'
    first = start.replace(minute=0, second=0, microsecond=0)
    if interval == 'day':
        first = first.replace(hour=0)
    step = timedelta(hours=1) if interval == 'hour' else timedelta(days=1)
    timeline = {}
    while first < end:
        timeline[first] = {'timestamp': first, **dict.fromkeys(DOMAINS, 0)}
        first += step
    window = {'$gte': start, '$lt': end}

    # Agent events are also mirrored into log_events for the general event search.
    network = {'attributes.agent_id': {'$exists': False},
               'attributes.agent_payload': {'$exists': False}}
    source_collections = {
        'network': (database.log_events, network),
        'system': (database.agent_logs, {}),
        'web': (database[WEB_BATCHES], {}),
    }
    traffic = {key: row.copy() for key, row in timeline.items()}
    for domain, (collection, filters) in source_collections.items():
        if domain == 'web':
            rows = time_series(
                collection, {'interval_end': {'$gt': start, '$lte': end}}, '$interval_start', interval,
                {'$sum': {'$map': {'input': {'$objectToArray': '$status_codes'}, 'as': 'code', 'in': '$$code.v'}}},
            )
        else:
            rows = time_series(collection, {'timestamp': window, **filters}, '$timestamp', interval)
        for row in rows:
            if row['_id'] in traffic:
                traffic[row['_id']][domain] = row['count']

    alerts = {key: row.copy() for key, row in timeline.items()}
    severity = dict.fromkeys(SEVERITIES, 0)
    domain_expr = {'$cond': [{'$in': ['$domain', ['system', 'web']]}, '$domain', 'network']}
    for row in database.siem_alerts.aggregate([
        {'$match': {'created_at': window}},
        {'$group': {'_id': {'timestamp': {'$dateTrunc': {'date': '$created_at', 'unit': interval}},
                            'domain': domain_expr, 'severity': '$severity'}, 'count': {'$sum': 1}}},
    ], maxTimeMS=QUERY_TIMEOUT):
        key = row['_id']
        alerts[key['timestamp']][key['domain']] += row['count']
        if key['severity'] in severity:
            severity[key['severity']] += row['count']

    queue = {domain: {'open': 0, 'acknowledged': 0} for domain in DOMAINS}
    for row in database.siem_alerts.aggregate([
        {'$match': {'status': {'$in': ['open', 'acknowledged']}}},
        {'$group': {'_id': {'domain': domain_expr, 'status': '$status'}, 'count': {'$sum': 1}}},
    ], maxTimeMS=QUERY_TIMEOUT):
        queue[row['_id']['domain']][row['_id']['status']] = row['count']

    sources = {}
    for domain, (collection, filters) in source_collections.items():
        recent = collection.find_one({**filters, 'received_at': {'$type': 'date'}},
                                     {'received_at': 1}, sort=[('received_at', -1)], max_time_ms=QUERY_TIMEOUT)
        sources[domain] = {
            'count': sum(row[domain] for row in traffic.values()),
            'last_received_at': recent['received_at'] if recent else None,
        }

    return {
        'hours': hours, 'interval': interval, 'since': start, 'until': end,
        'alert_series': list(alerts.values()), 'log_series': list(traffic.values()),
        'alert_totals': {domain: sum(row[domain] for row in alerts.values()) for domain in DOMAINS},
        'alert_severities': severity, 'alert_queue': queue, 'sources': sources,
        'active_incidents': database.siem_incidents.count_documents({'status': {'$ne': 'closed'}}),
        'enabled_rules': database.siem_rules.count_documents({'enabled': True}),
    }
