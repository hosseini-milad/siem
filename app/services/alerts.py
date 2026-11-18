from uuid import NAMESPACE_URL, uuid5

from app.services import siem


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
