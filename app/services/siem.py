"""Persistent SIEM workflows; rules are structured data, never executable expressions."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import NAMESPACE_URL, uuid4, uuid5

from pymongo import UpdateOne

from app.models.log import log_document, public_document


def now():
    return datetime.now(timezone.utc)


def public(row):
    return public_document(row) if row is not None else None


def page(collection, query, limit, offset):
    return {'items': [public(row) for row in collection.find(query).sort([('created_at', -1), ('_id', -1)]).skip(offset).limit(limit)],
            'total': collection.count_documents(query), 'limit': limit, 'offset': offset}


def create(collection, body):
    stamp = now()
    row = {'_id': str(uuid4()), **body, 'created_at': stamp, 'updated_at': stamp}
    collection.insert_one(row)
    return public(row)


def require_links(collection, ids):
    ids = list(map(str, ids))
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate evidence identifiers')
    if collection.count_documents({'_id': {'$in': ids}}) != len(ids):
        raise ValueError('Some linked evidence was not found')
    return ids


def update_status(collection, identity, status):
    result = collection.update_one({'_id': identity}, {'$set': {'status': status, 'updated_at': now()}})
    return public(collection.find_one({'_id': identity})) if result.matched_count else None


def emit_alert(db, identity, body):
    stamp = now()
    return db.siem_alerts.update_one({'_id': identity}, {'$setOnInsert': {
        **body, 'status': 'open', 'created_at': stamp, 'updated_at': stamp}}, upsert=True).upserted_id is not None


def evaluate_rules(db):
    stamp = now()
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


def fingerprint(batch):
    return hashlib.sha256(json.dumps(batch.model_dump(mode='json'), sort_keys=True,
                                     separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def prepare_batch(db, batch, state):
    identity, digest = str(batch.batch_id), fingerprint(batch)
    db.ingestion_batches.update_one({'_id': identity}, {'$setOnInsert': {
        'fingerprint': digest, 'status': state, 'events': len(batch.events), 'created_at': now()}}, upsert=True)
    if db.ingestion_batches.find_one({'_id': identity})['fingerprint'] != digest:
        raise ValueError('batch_id was already used with a different payload')
    return identity


def receive_batch(db, batch):
    identity = prepare_batch(db, batch, 'processing')
    db.ingestion_batches.update_one({'_id': identity, 'status': {'$ne': 'stored'}},
                                     {'$set': {'status': 'processing', 'updated_at': now()}})
    operations = []
    for index, event in enumerate(batch.events):
        document = log_document(event)
        document['_id'] = str(uuid5(batch.batch_id, str(index)))
        operations.append(UpdateOne({'_id': document['_id']}, {'$setOnInsert': document}, upsert=True))
    result = db.log_events.bulk_write(operations)
    db.ingestion_batches.update_one({'_id': identity}, {'$set': {'status': 'stored', 'stored': len(batch.events),
                                                               'updated_at': now()}})
    return {'batch_id': identity, 'status': 'stored', 'inserted': result.upserted_count,
            'deduplicated': len(batch.events) - result.upserted_count}


def overview(db, hours):
    since = now() - timedelta(hours=hours)
    query = {'timestamp': {'$gte': since}}
    by_level = list(db.log_events.aggregate([{'$match': query}, {'$group': {'_id': '$level', 'count': {'$sum': 1}}}]))
    by_source = list(db.log_events.aggregate([{'$match': query}, {'$group': {'_id': '$source', 'count': {'$sum': 1}}},
                                             {'$sort': {'count': -1}}, {'$limit': 10}]))
    trend = list(db.log_events.aggregate([{'$match': query}, {'$group': {
        '_id': {'$dateTrunc': {'date': '$timestamp', 'unit': 'hour'}}, 'count': {'$sum': 1}}}, {'$sort': {'_id': 1}}]))
    return {'since': since, 'hours': hours, 'event_count': sum(item['count'] for item in by_level),
            'open_alerts': db.siem_alerts.count_documents({'status': {'$in': ['open', 'acknowledged']}}),
            'active_incidents': db.siem_incidents.count_documents({'status': {'$ne': 'closed'}}),
            'enabled_rules': db.siem_rules.count_documents({'enabled': True}),
            'levels': [{'level': item['_id'], 'count': item['count']} for item in by_level],
            'top_sources': [{'source': item['_id'], 'count': item['count']} for item in by_source],
            'hourly_events': [{'timestamp': item['_id'], 'count': item['count']} for item in trend]}
