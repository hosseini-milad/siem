"""Live threshold rules over retained, signed web request details."""
import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
import logging
from hashlib import sha256
from types import SimpleNamespace
from uuid import uuid4

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
from starlette.concurrency import run_in_threadpool

from app.services.alerts import emit_alert
from app.services.owasp_signals import BATCHES, COLLECTION as SIGNAL_COLLECTION, SIGNALS
from app.services.web_access import RECORDS

SETTINGS = 'web_alert_settings'
COOLDOWNS = 'web_alert_cooldowns'
MONITORED = 'web_alert_monitored_services'
BASE_RULE = {'enabled': True, 'window_minutes': 5, 'cooldown_minutes': 15, 'severity': 'medium'}
DEFAULTS = {
    **{key: {**BASE_RULE, 'threshold': 1} for key, _, _ in SIGNALS.values()},
    'access_denied': {**BASE_RULE, 'threshold': 5},
    'login_failure': {**BASE_RULE, 'threshold': 5},
    'server_error': {**BASE_RULE, 'threshold': 10},
    'logging_health': {**BASE_RULE, 'threshold': 3},
}
REQUEST_RULES = {
    'login_failure': ('login_failure', 401, 'A07', 'Repeated web authentication failures'),
    'access_denied': ('access_denied', 403, 'A01', 'Repeated web access denials'),
}
LOGGER = logging.getLogger('uvicorn.error.owasp')


def settings(database):
    stored = database[SETTINGS].find_one({'_id': 'default'}, {'_id': 0}) or {}
    return {key: {**value, **stored.get(key, {})} for key, value in DEFAULTS.items()}


def emit_with_cooldown(database, key, now, minutes, body, *, collection_name=COOLDOWNS):
    state_collection = database[collection_name]
    pending = {'id': str(uuid4()), 'body': body}
    query = {'_id': key, 'pending': {'$exists': False},
             'last_triggered_at': {'$lte': now - timedelta(minutes=minutes)}}
    try:
        state = state_collection.find_one_and_update(
            query, {'$set': {'last_triggered_at': now, 'pending': pending}},
            upsert=True, return_document=ReturnDocument.AFTER,
        )
    except DuplicateKeyError:
        state = state_collection.find_one({'_id': key})
    if not state or not (pending := state.get('pending')):
        return 0
    try:
        created = emit_alert(database, pending['id'], pending['body'])
    except DuplicateKeyError:
        # A concurrent retry may have flushed the same reservation.
        created = False
        if database.siem_alerts.find_one({'_id': pending['id']}, {'_id': 1}) is None:
            raise
    state_collection.update_one({'_id': key, 'pending.id': pending['id']}, {'$unset': {'pending': ''}})
    return int(created)


def emit_finding(database, key, service, identity, now, rule, category, title, evidence):
    scope = sha256(f'{key}\0{service}\0{identity or ""}'.encode()).hexdigest()
    return emit_with_cooldown(database, scope, now, rule['cooldown_minutes'], {
        'title': title, 'description': 'A configured OWASP telemetry rule was triggered.',
        'severity': rule['severity'], 'source': service, 'kind': 'web_threshold',
        'domain': 'web', 'owasp_category': category, 'event_ids': [],
        'evidence': {'rule': key, 'window_minutes': rule['window_minutes'], **evidence},
    })


def inspect_batch(database, service, events, now):
    created = 0
    records = database[RECORDS]
    configured = settings(database)
    for key, (marker, status, category, title) in REQUEST_RULES.items():
        rule = configured[key]
        if not rule['enabled']:
            continue
        start = now - timedelta(minutes=rule['window_minutes'])
        candidates = [event for event in events
                      if start <= event.timestamp <= now and event.status == status and event.security_event == marker]
        subjects = {event.auth_subject for event in candidates if event.auth_subject}
        sources = {str(event.source_ip) for event in candidates if event.source_ip and not event.auth_subject}
        if not subjects and not sources:
            continue
        match = {'service': service, 'security_event': marker, 'status': status,
                 'timestamp': {'$gte': start, '$lte': now}, '$or': [
                     {'auth_subject': {'$in': list(subjects)}},
                     {'auth_subject': None, 'source_ip': {'$in': list(sources)}},
                 ]}
        for row in records.aggregate([
            {'$match': match},
            {'$group': {'_id': {'scope': {'$ifNull': ['$auth_subject', '$source_ip']}, 'request_id': '$request_id'}}},
            {'$group': {'_id': '$_id.scope', 'count': {'$sum': 1}}},
            {'$match': {'count': {'$gte': rule['threshold']}}},
        ], maxTimeMS=10000):
            identity = row['_id']
            subject = identity if identity in subjects else None
            address = None if subject else identity
            evidence_match = {**match, 'auth_subject': subject, **({'source_ip': address} if address else {})}
            evidence = list(records.aggregate([
                {'$match': evidence_match},
                {'$sort': {'timestamp': -1, '_id': -1}},
                {'$group': {'_id': '$request_id', 'record_id': {'$first': '$_id'},
                            'timestamp': {'$first': '$timestamp'}}},
                {'$sort': {'timestamp': -1, 'record_id': -1}},
                {'$limit': 20},
            ], maxTimeMS=10000))
            created += emit_finding(database, key, service, identity, now, rule, category, title, {
                'source_ip': address, 'auth_subject': subject, 'observed_count': row['count'],
                'threshold': rule['threshold'], 'web_record_ids': [item['record_id'] for item in evidence],
                'occurred_at': evidence[0]['timestamp'] if evidence else None,
            })
    return created


def inspect_signals(database, service, signals, now):
    created = 0
    configured = settings(database)
    collection = database[SIGNAL_COLLECTION]
    for signal in {event.signal for event in signals}:
        key, category, title = SIGNALS[signal]
        rule = configured[key]
        start = now - timedelta(minutes=rule['window_minutes'])
        if not rule['enabled'] or not any(
            event.signal == signal and start <= event.timestamp <= now for event in signals
        ):
            continue
        query = {'service': service, 'signal': signal, 'timestamp': {'$gte': start, '$lte': now}}
        count = collection.count_documents(query, maxTimeMS=10000)
        if count >= rule['threshold']:
            evidence = list(collection.find(query, {'timestamp': 1})
                            .sort([('timestamp', -1), ('_id', -1)]).limit(20).max_time_ms(10000))
            created += emit_finding(database, key, service, signal, now, rule, category, title, {
                'signal': signal, 'observed_count': count, 'threshold': rule['threshold'],
                'security_signal_ids': [row['_id'] for row in evidence],
                'occurred_at': evidence[0]['timestamp'] if evidence else None,
            })
    return created


def inspect_metrics(database, service, now):
    created = 0
    configured = settings(database)
    for key, category, title in (
        ('server_error', 'A10', 'Web service error burst'),
        ('logging_health', 'A09', 'Invalid lines in web security telemetry'),
    ):
        rule = configured[key]
        if not rule['enabled']:
            continue
        start = now - timedelta(minutes=rule['window_minutes'])
        batches = database[BATCHES].find(
            {'service': service, 'interval_end': {'$gt': start, '$lte': now}},
            {'status_codes': 1, 'invalid_lines': 1},
        ).sort([('interval_end', -1), ('_id', -1)]).max_time_ms(10000)
        seen = 0
        ids = []
        for batch in batches:
            count = (sum(count for code, count in batch['status_codes'].items() if code.startswith('5'))
                     if key == 'server_error' else batch.get('invalid_lines', 0))
            seen += count
            if count and len(ids) < 20:
                ids.append(batch['_id'])
        if seen >= rule['threshold']:
            evidence = {'observed_count': seen, 'threshold': rule['threshold'], 'web_batch_ids': ids}
            if key == 'server_error':
                details = database[RECORDS].find({
                    'service': service, 'status': {'$gte': 500, '$lte': 599},
                    'timestamp': {'$gte': start, '$lte': now},
                }, {'_id': 1}).sort([('timestamp', -1), ('_id', -1)]).limit(20).max_time_ms(10000)
                evidence['web_record_ids'] = [detail['_id'] for detail in details]
            created += emit_finding(database, key, service, key, now, rule, category, title, evidence)
    return created


def check_collectors(database, services, now):
    created = 0
    rule = settings(database)['logging_health']
    monitored = database[MONITORED]
    for service in services:
        registered = monitored.find_one_and_update({'_id': service}, {'$setOnInsert': {'since': now}},
                                                   upsert=True, return_document=ReturnDocument.AFTER)
        if not rule['enabled']:
            continue
        latest = database[BATCHES].find_one(
            {'service': service, 'interval_end': {'$lte': now}},
            {'interval_end': 1}, sort=[('interval_end', -1)], max_time_ms=10000,
        )
        last_interval = latest['interval_end'] if latest else None
        age = now - max(registered['since'], last_interval or registered['since'])
        if age >= timedelta(minutes=rule['window_minutes']):
            created += emit_finding(database, 'logging_health', service, 'missing_heartbeat', now, rule, 'A09',
                         'No recent web collector heartbeat', {
                             'signal': 'missing_heartbeat', 'last_interval_end': last_interval,
                             'monitored_since': registered['since'], 'silent_seconds': int(age.total_seconds()),
                         })
    return created


def evaluate_current(database, services, now):
    configured = settings(database)
    window = {'$gte': now - timedelta(minutes=max(rule['window_minutes'] for rule in configured.values())),
              '$lte': now}
    results = []
    for service in services:
        request_rows = list(database[RECORDS].find({
            'service': service, 'timestamp': window, 'security_event': {'$in': ['login_failure', 'access_denied']},
        }, {'timestamp': 1, 'status': 1, 'security_event': 1, 'auth_subject': 1, 'source_ip': 1})
            .sort([('timestamp', -1), ('_id', -1)]).limit(5001).max_time_ms(10000))
        signals = database[SIGNAL_COLLECTION].aggregate([
            {'$match': {'service': service, 'timestamp': window, 'signal': {'$in': list(SIGNALS)}}},
            {'$group': {'_id': '$signal', 'timestamp': {'$max': '$timestamp'}}},
        ], maxTimeMS=10000)
        created = inspect_signals(database, service, [
            SimpleNamespace(signal=row['_id'], timestamp=row['timestamp']) for row in signals
        ], now)
        created += inspect_metrics(database, service, now)
        created += check_collectors(database, (service,), now)
        truncated = len(request_rows) > 5000
        if not truncated:
            candidates = [SimpleNamespace(**{'auth_subject': None, 'source_ip': None, **row}) for row in request_rows]
            created += inspect_batch(database, service, candidates, now)
        results.append({'service': service, 'alerts_created': created, 'request_rules_skipped': truncated})
    return {'items': results, 'alerts_created': sum(row['alerts_created'] for row in results)}


@asynccontextmanager
async def monitor_collectors(database, services):
    if not services:
        yield
        return

    async def monitor():
        while True:
            try:
                await run_in_threadpool(check_collectors, database, services, datetime.now(timezone.utc))
            except PyMongoError:
                LOGGER.exception('Could not evaluate web collector heartbeat')
            await asyncio.sleep(30)

    task = asyncio.create_task(monitor())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
