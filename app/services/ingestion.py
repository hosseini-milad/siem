import hashlib
import json
from uuid import uuid5

from pymongo import UpdateOne

from app.models.log import COLLECTION, log_document
from app.services.siem import now


def fingerprint(batch):
    return hashlib.sha256(json.dumps(batch.model_dump(mode='json'), sort_keys=True,
                                     separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def prepare_batch(db, batch):
    identity, digest = str(batch.batch_id), fingerprint(batch)
    db.ingestion_batches.update_one({'_id': identity}, {'$setOnInsert': {
        'fingerprint': digest, 'status': 'processing', 'events': len(batch.events), 'created_at': now()}}, upsert=True)
    if db.ingestion_batches.find_one({'_id': identity})['fingerprint'] != digest:
        raise ValueError('batch_id was already used with a different payload')
    return identity


def receive_batch(db, batch):
    identity = prepare_batch(db, batch)
    db.ingestion_batches.update_one({'_id': identity, 'status': {'$ne': 'stored'}},
                                     {'$set': {'status': 'processing', 'updated_at': now()}})
    operations = []
    for index, event in enumerate(batch.events):
        document = log_document(event)
        document['_id'] = str(uuid5(batch.batch_id, str(index)))
        operations.append(UpdateOne({'_id': document['_id']}, {'$setOnInsert': document}, upsert=True))
    result = db[COLLECTION].bulk_write(operations)
    db.ingestion_batches.update_one({'_id': identity}, {'$set': {'status': 'stored', 'stored': len(batch.events),
                                                               'updated_at': now()}})
    return {'batch_id': identity, 'status': 'stored', 'inserted': result.upserted_count,
            'deduplicated': len(batch.events) - result.upserted_count}
