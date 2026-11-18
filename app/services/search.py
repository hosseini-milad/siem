"""Read operational events directly from MongoDB."""
import re

from app.models.log import COLLECTION, public_document

QUERY_TIMEOUT_MS = 30_000


def event_filter(*, source=None, level=None, start=None, end=None, q=''):
    query = {}
    if source is not None:
        query['source'] = source
    if level is not None:
        query['level'] = level
    time_range = {}
    if start is not None:
        time_range['$gte'] = start
    if end is not None:
        time_range['$lte'] = end
    if time_range:
        query['timestamp'] = time_range
    if q.strip():
        literal = {'$regex': re.escape(q.strip()), '$options': 'i'}
        query['$or'] = [{'message': literal}, {'source': literal}]
    return query


def page(database, query, limit, offset, *, timeout_ms=None):
    collection = database[COLLECTION]
    rows = collection.find(query).sort([('timestamp', -1), ('_id', -1)]).skip(offset).limit(limit)
    count_options = {}
    if timeout_ms is not None:
        rows = rows.max_time_ms(timeout_ms)
        count_options['maxTimeMS'] = timeout_ms
    return {'items': [public_document(row) for row in rows],
            'total': collection.count_documents(query, **count_options), 'limit': limit, 'offset': offset}


def statistics(database, query, interval):
    pipeline = [
        {'$match': query},
        {'$facet': {
            'levels': [
                {'$group': {'_id': '$level', 'count': {'$sum': 1}}},
                {'$sort': {'_id': 1}},
            ],
            'sources': [
                {'$group': {'_id': '$source', 'count': {'$sum': 1}}},
                {'$sort': {'count': -1, '_id': 1}},
                {'$limit': 10},
            ],
            'series': [
                {'$group': {
                    '_id': {'$dateTrunc': {'date': '$timestamp', 'unit': interval, 'timezone': 'UTC'}},
                    'count': {'$sum': 1},
                }},
                {'$sort': {'_id': 1}},
            ],
        }},
    ]
    result = next(database[COLLECTION].aggregate(pipeline, maxTimeMS=QUERY_TIMEOUT_MS))
    return {
        'event_count': sum(row['count'] for row in result['levels']),
        'levels': [{'level': row['_id'], 'count': row['count']} for row in result['levels']],
        'top_sources': [{'source': row['_id'], 'count': row['count']} for row in result['sources']],
        'series': [{'timestamp': row['_id'], 'count': row['count']} for row in result['series']],
    }
