from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

from app.services import siem
from app.services.agent_ingestion import AGENT_LOGS
from app.services.system_log_ml import AGENT_LOG_LABELS
from app.services.web_access import RECORDS


def emit_alert(db, identity, body):
    stamp = siem.now()
    return db.siem_alerts.update_one({'_id': identity}, {'$setOnInsert': {
        **body, 'status': 'open', 'created_at': stamp, 'updated_at': stamp}}, upsert=True).upserted_id is not None


def alerts_from_predictions(db, minimum, limit):
    created = scanned = 0
    for prediction in db.ml_predictions.find({'attack_probability': {'$gte': minimum}}).sort('_id', 1).limit(limit):
        scanned += 1
        identity = str(uuid5(NAMESPACE_URL, 'siem-ml:' + str(prediction['_id'])))
        created += emit_alert(db, identity, {
            'title': 'Machine learning attack prediction', 'description': 'Review the source record and model probability.',
            'severity': 'high', 'source': 'machine_learning', 'kind': 'ml', 'event_ids': [],
            'evidence': {'original_id': prediction.get('original_id', prediction['_id']),
                         'attack_probability': prediction['attack_probability'],
                         'predicted_at': prediction.get('predicted_at')}})
    return {'scanned_predictions': scanned, 'alerts_created': created, 'deduplicated': scanned - created}


def domain_filter(domain):
    if domain in ('system', 'web'):
        return {'domain': domain}
    if domain == 'network':
        return {'domain': {'$nin': ['system', 'web']}}
    return {}


def alert_summary(db, domain, days):
    today = siem.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start = today - timedelta(days=days - 1)
    query = {**domain_filter(domain), 'created_at': {'$gte': start, '$lt': today + timedelta(days=1)}}
    timeline = {(start + timedelta(days=i)).date().isoformat(): 0 for i in range(days)}
    severities = dict.fromkeys(('critical', 'high', 'medium', 'low'), 0)
    for row in db.siem_alerts.aggregate([
        {'$match': query},
        {'$group': {'_id': {
            'day': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
            'severity': '$severity',
        }, 'count': {'$sum': 1}}},
    ], maxTimeMS=30000):
        timeline[row['_id']['day']] += row['count']
        severity = row['_id']['severity']
        if severity in severities:
            severities[severity] += row['count']
    return {
        'days': days, 'total': sum(timeline.values()),
        'series': [{'day': day, 'count': count} for day, count in timeline.items()],
        'severities': severities,
    }


def alert_from_system_log(db, body):
    identity = str(uuid5(NAMESPACE_URL, 'siem-system-log:' + body.log_id))
    existing = db.siem_alerts.find_one({'_id': identity})
    if existing is not None:
        return siem.public(existing)
    log = db[AGENT_LOG_LABELS].find_one({'_id': body.log_id}, {'features': 0})
    if log is None:
        return None
    emit_alert(db, identity, {
        'title': body.title, 'description': body.description, 'severity': body.severity,
        'domain': 'system', 'kind': 'system_log', 'source': log['agent_id'], 'event_ids': [],
        'evidence': {
            'agent_log_id': body.log_id, 'predicted_label': log['predicted_label'],
            'prediction_confidence': log['prediction_confidence'], 'model_id': log['model_id'],
        },
    })
    return siem.public(db.siem_alerts.find_one({'_id': identity}))


def alert_evidence(db, alert):
    references = []
    event_ids = alert.get('event_ids', [])
    if event_ids:
        events = {row['_id']: row for row in db.log_events.find({'_id': {'$in': event_ids}})}
        references.extend({
            'collection': 'log_events', 'id': identity, 'record': siem.public(events.get(identity)),
        } for identity in event_ids)
    evidence = alert.get('evidence') or {}
    if alert.get('kind') == 'ml' and isinstance(evidence.get('original_id'), str):
        identity = evidence['original_id']
        for collection in ('ml_predictions', 'standard_records', 'dataset_records', 'log_events'):
            row = db[collection].find_one(
                {'original_id': identity} if collection == 'standard_records' else {'_id': identity})
            if row is not None or collection in ('dataset_records', 'ml_predictions'):
                references.append({'collection': collection, 'id': identity, 'record': siem.public(row)})
    if alert.get('kind') == 'system_log' and isinstance(evidence.get('agent_log_id'), str):
        identity = evidence['agent_log_id']
        for collection in (AGENT_LOG_LABELS, AGENT_LOGS):
            row = db[collection].find_one({'_id': identity})
            references.append({'collection': collection, 'id': identity, 'record': siem.public(row)})
    if alert.get('kind') == 'web_threshold':
        ids = evidence.get('web_record_ids', [])
        rows = {row['_id']: row for row in db[RECORDS].find({'_id': {'$in': ids}})}
        references.extend({'collection': RECORDS, 'id': identity, 'record': siem.public(rows.get(identity))}
                          for identity in ids)
    return references
