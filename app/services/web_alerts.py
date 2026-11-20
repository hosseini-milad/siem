"""Live threshold rules over retained, signed web request details."""
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.services.alerts import emit_alert
from app.services.web_access import RECORDS

SETTINGS = 'web_alert_settings'
COOLDOWNS = 'web_alert_cooldowns'
DEFAULTS = {
    'login_failure': {'enabled': True, 'threshold': 5, 'window_minutes': 5,
                      'cooldown_minutes': 15, 'severity': 'medium'},
    'server_error': {'enabled': True, 'threshold': 10, 'window_minutes': 5,
                     'cooldown_minutes': 15, 'severity': 'medium'},
}
RULES = {
    'login_failure': ({'security_event': 'login_failure', 'status': 401}, 'Repeated web login failures'),
    'server_error': ({'status': {'$gte': 500, '$lte': 599}}, 'Web service error burst'),
}


def settings(database):
    stored = database[SETTINGS].find_one({'_id': 'default'}, {'_id': 0}) or {}
    return {key: {**value, **stored.get(key, {})} for key, value in DEFAULTS.items()}


def emit_with_cooldown(database, key, now, minutes, body):
    state_collection = database[COOLDOWNS]
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
        return
    try:
        emit_alert(database, pending['id'], pending['body'])
    except DuplicateKeyError:
        # A concurrent retry may have flushed the same reservation.
        if database.siem_alerts.find_one({'_id': pending['id']}, {'_id': 1}) is None:
            raise
    state_collection.update_one({'_id': key, 'pending.id': pending['id']}, {'$unset': {'pending': ''}})


def inspect_batch(database, service, events, now):
    records = database[RECORDS]
    configured = settings(database)
    for key, (conditions, title) in RULES.items():
        rule = configured[key]
        if not rule['enabled']:
            continue
        start = now - timedelta(minutes=rule['window_minutes'])
        candidates = [event for event in events if start <= event.timestamp <= now]
        if key == 'login_failure':
            failures = [event for event in candidates
                        if event.status == 401 and event.security_event == 'login_failure']
            subjects = {event.auth_subject for event in failures if event.auth_subject}
            sources = {str(event.source_ip) for event in failures if event.source_ip and not event.auth_subject}
            if not subjects and not sources:
                continue
            group = {'$ifNull': ['$auth_subject', '$source_ip']}
            conditions = {**conditions, '$or': [
                {'auth_subject': {'$in': list(subjects)}},
                {'auth_subject': None, 'source_ip': {'$in': list(sources)}},
            ]}
        else:
            if not any(event.status >= 500 for event in candidates):
                continue
            group = None
        match = {'service': service, **conditions, 'timestamp': {'$gte': start, '$lte': now}}
        for row in records.aggregate([
            {'$match': match},
            {'$group': {'_id': {'scope': group, 'request_id': '$request_id'}}},
            {'$group': {'_id': '$_id.scope', 'count': {'$sum': 1}}},
            {'$match': {'count': {'$gte': rule['threshold']}}},
        ], maxTimeMS=10000):
            identity = row['_id']
            subject = identity if key == 'login_failure' and identity in subjects else None
            address = identity if key == 'login_failure' and subject is None else None
            evidence_match = dict(match)
            if subject is not None:
                evidence_match['auth_subject'] = subject
            elif address is not None:
                evidence_match.update(auth_subject=None, source_ip=address)
            ids = [item['record_id'] for item in records.aggregate([
                {'$match': evidence_match},
                {'$sort': {'timestamp': -1, '_id': -1}},
                {'$group': {'_id': '$request_id', 'record_id': {'$first': '$_id'},
                            'timestamp': {'$first': '$timestamp'}}},
                {'$sort': {'timestamp': -1, 'record_id': -1}},
                {'$limit': 20},
            ], maxTimeMS=10000)]
            scope = sha256(f'{key}\0{service}\0{address or ""}'.encode()).hexdigest()
            emit_with_cooldown(database, scope, now, rule['cooldown_minutes'], {
                'title': title, 'description': 'A configured threshold was reached in retained web request details.',
                'severity': rule['severity'], 'source': service, 'kind': 'web_threshold',
                'domain': 'web', 'event_ids': [],
                'evidence': {
                    'rule': key, 'source_ip': address, 'auth_subject': subject, 'observed_count': row['count'],
                    'threshold': rule['threshold'], 'window_minutes': rule['window_minutes'],
                    'web_record_ids': ids,
                },
            })
