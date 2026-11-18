"""Common persistence operations for alerts, rules, and incidents."""
from datetime import datetime, timezone
from uuid import uuid4

from app.models.log import public_document


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
