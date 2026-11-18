from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

from app.services import siem
from app.services.alerts import emit_alert


def evaluate_rules(db):
    stamp = siem.now()
    evaluated = inserted = 0
    outcomes = []
    for rule in db.siem_rules.find({'enabled': True}).limit(1000):
        cutoff = stamp - timedelta(seconds=rule['lookback_seconds'])
        query = {'timestamp': {'$gte': cutoff, '$lte': stamp}}
        if rule.get('source'):
            query['source'] = rule['source']
        if rule.get('level'):
            query['level'] = rule['level']
        groups = db.log_events.aggregate([
            {'$match': query}, {'$group': {'_id': '$source', 'count': {'$sum': 1}}},
            {'$match': {'count': {'$gte': rule['threshold']}}}, {'$sort': {'_id': 1}}, {'$limit': 1000}],
            maxTimeMS=30000)
        matches = created = 0
        for group in groups:
            matches += 1
            bucket = int(stamp.timestamp()) // rule['cooldown_seconds']
            identity = str(uuid5(NAMESPACE_URL, f"siem-rule:{rule['_id']}:{group['_id']}:{bucket}"))
            created += emit_alert(db, identity, {
                'title': rule['name'], 'description': rule['description'], 'severity': rule['severity'],
                'source': group['_id'], 'rule_id': rule['_id'], 'kind': 'threshold', 'event_ids': [],
                'evidence': {'count': group['count'], 'threshold': rule['threshold'],
                             'window_start': cutoff, 'window_end': stamp, 'level': rule.get('level')}})
        evaluated += 1
        inserted += created
        outcomes.append({'rule_id': rule['_id'], 'matching_sources': matches, 'alerts_created': created})
    return {'evaluated_rules': evaluated, 'alerts_created': inserted, 'rules': outcomes, 'evaluated_at': stamp}
