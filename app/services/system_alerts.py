"""Configurable Windows Security thresholds over stored Agent logs."""
from collections import defaultdict
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address
import re

from app.services.agent_ingestion import AGENT_LOGS
from app.services.web_alerts import emit_with_cooldown

SETTINGS = 'system_alert_settings'
COOLDOWNS = 'system_alert_cooldowns'
BASE = {'enabled': True, 'threshold': 1, 'window_minutes': 5, 'cooldown_minutes': 15, 'severity': 'medium'}
DEFAULTS = {
    'logon_failure': {**BASE, 'threshold': 8, 'window_minutes': 4},
    'account_lockout': {**BASE},
    'audit_log_cleared': {**BASE, 'severity': 'high'},
    'audit_policy_changed': {**BASE},
    'service_installed': {**BASE},
}
RULES = {
    4625: ('logon_failure', 'Repeated Windows logon failures'),
    4740: ('account_lockout', 'Windows account locked out'),
    1102: ('audit_log_cleared', 'Windows Security audit log cleared'),
    4719: ('audit_policy_changed', 'Windows audit policy changed'),
    4697: ('service_installed', 'New Windows service installed'),
}
SECURITY_CHANNEL = re.compile(r'^security$', re.IGNORECASE)


def settings(database):
    stored = database[SETTINGS].find_one({'_id': 'default'}, {'_id': 0}) or {}
    return {key: {**rule, **stored.get(key, {})} for key, rule in DEFAULTS.items()}


def safe_text(value):
    return value.strip()[:255] if isinstance(value, str) else ''


def classify(row):
    channel = row.get('log') or row.get('channel') or row.get('Channel')
    if safe_text(channel).casefold() != 'security':
        return None
    value = row.get('event_id', row.get('EventID'))
    try:
        if isinstance(value, bool):
            return None
        number = int(value) if isinstance(value, (str, int)) else None
    except ValueError:
        return None
    return number if number in RULES else None


def identity(event_id, row):
    host = safe_text(row.get('system_id') or row.get('mac') or row.get('computer') or row.get('agent_id'))
    if not host:
        return None
    account = safe_text(row.get('TargetUserName') or row.get('targetUserName'))
    domain = safe_text(row.get('TargetDomainName') or row.get('targetDomainName'))
    if event_id == 4625:
        address = safe_text(row.get('IpAddress') or row.get('ipAddress'))
        try:
            parsed = ip_address(address)
            if not parsed.is_unspecified and not parsed.is_loopback and '%' not in address:
                return host.casefold(), f'ip:{parsed}'
        except ValueError:
            pass
        if account and account != '-':
            return host.casefold(), f'account:{domain.casefold()}:{account.casefold()}'
    elif event_id == 4740 and account and account != '-':
        return host.casefold(), f'account:{domain.casefold()}:{account.casefold()}'
    return host.casefold(), ''


def evaluate(database, now, candidates=None):
    if candidates is not None:
        candidates = [(event_id, row) for row in candidates if (event_id := classify(row)) is not None]
        if not candidates:
            return {'alerts_created': 0, 'request_rules_skipped': False, 'matched_events': 0}
    configured = settings(database)
    relevant = None if candidates is None else {
        (event_id, scope) for event_id, row in candidates
        if (scope := identity(event_id, row)) is not None
        and row['timestamp'] <= now and row['timestamp'] >= now - timedelta(
            minutes=configured[RULES[event_id][0]]['window_minutes'])
    }
    active = {event_id: configured[key] for event_id, (key, _) in RULES.items()
              if configured[key]['enabled'] and (relevant is None or any(item[0] == event_id for item in relevant))}
    if not active:
        return {'alerts_created': 0, 'request_rules_skipped': False, 'matched_events': 0}

    oldest = now - timedelta(minutes=max(rule['window_minutes'] for rule in active.values()))
    ids = [value for event_id in active for value in (event_id, str(event_id))]
    collection = database[AGENT_LOGS]
    cursor = collection.find({
        'timestamp': {'$gte': oldest, '$lte': now},
        '$and': [
            {'$or': [{key: SECURITY_CHANNEL} for key in ('log', 'channel', 'Channel')]},
            {'$or': [{'event_id': {'$in': ids}}, {'EventID': {'$in': ids}}]},
        ],
    }, {key: 1 for key in ('timestamp', 'log', 'channel', 'Channel', 'event_id', 'EventID', 'system_id', 'mac',
                             'computer', 'agent_id', 'TargetUserName', 'targetUserName', 'TargetDomainName',
                             'targetDomainName', 'IpAddress', 'ipAddress')}).sort(
        [('timestamp', -1), ('_id', -1)]).limit(5001).max_time_ms(10000)
    with cursor:
        rows = list(cursor)
    if len(rows) > 5000:
        return {'alerts_created': 0, 'request_rules_skipped': True, 'matched_events': 0}

    groups = defaultdict(list)
    for row in rows:
        event_id = classify(row)
        if event_id not in active:
            continue
        scope = identity(event_id, row)
        rule = active[event_id]
        if not scope or (relevant is not None and (event_id, scope) not in relevant):
            continue
        if row['timestamp'] >= now - timedelta(minutes=rule['window_minutes']):
            groups[event_id, scope].append(row)

    created = 0
    for (event_id, scope), evidence in groups.items():
        rule = active[event_id]
        if len(evidence) < rule['threshold']:
            continue
        key, title = RULES[event_id]
        host, actor = scope
        token = sha256(f'{key}\0{host}\0{actor}'.encode()).hexdigest()
        created += emit_with_cooldown(database, token, now, rule['cooldown_minutes'], {
            'title': title, 'description': 'A configured Windows Security event threshold was reached.',
            'severity': rule['severity'], 'source': host, 'domain': 'system',
            'kind': 'system_threshold', 'event_ids': [],
            'evidence': {
                'rule': key, 'windows_event_id': event_id, 'channel': 'Security',
                'observed_count': len(evidence), 'threshold': rule['threshold'],
                'window_minutes': rule['window_minutes'], 'agent_log_ids': [row['_id'] for row in evidence[:20]],
                'occurred_at': evidence[0]['timestamp'],
                **({'source_ip': actor.removeprefix('ip:')} if actor.startswith('ip:') else {}),
            },
        }, collection_name=COOLDOWNS)
    return {'alerts_created': created, 'request_rules_skipped': False,
            'matched_events': sum(map(len, groups.values()))}
