"""Read raw records alongside the processing results linked to their original IDs."""
import re

from app.models.log import COLLECTION

TIMEOUT_MS = 30_000
RISK_BANDS = {
    'low': {'$gte': 0, '$lt': .35},
    'medium': {'$gte': .35, '$lt': .65},
    'high': {'$gte': .65, '$lt': .85},
    'critical': {'$gte': .85, '$lte': 1},
}


def convert(value, target):
    return {'$convert': {'input': value, 'to': target, 'onError': None, 'onNull': None}}


def dataset_fields():
    # CSV headers and values are stored verbatim. Normalize a query projection only.
    aliases = {
        'timestamp': ('timestamp',), 'source_ip': ('src ip', 'source ip'),
        'destination_ip': ('dst ip', 'destination ip'), 'source_port': ('src port', 'source port'),
        'destination_port': ('dst port', 'destination port'), 'protocol': ('protocol',), 'label': ('label',),
    }
    projection = {field: {'$ifNull': [*['$columns.' + alias for alias in names], None]}
                  for field, names in aliases.items()}
    return [
        {'$project': {'raw': '$$ROOT', 'columns': {'$arrayToObject': {'$map': {
            'input': {'$objectToArray': '$$ROOT'}, 'as': 'field',
            'in': {'k': {'$toLower': {'$trim': {'input': '$$field.k'}}}, 'v': '$$field.v'},
        }}}}},
        {'$project': {**projection, 'raw': 1, 'source': {'$literal': 'network-flow'},
                      'message': {'$literal': 'جریان ترافیک شبکه'}, 'level': {'$literal': None}}},
        {'$set': {'timestamp': dataset_timestamp('$timestamp')}},
    ]


def dataset_timestamp(value):
    # Small numeric values are relative times, without a known calendar date.
    return {'$let': {'vars': {'epoch': convert(value, 'double')}, 'in': {'$switch': {
        'branches': [
            {'case': {'$eq': ['$$epoch', None]}, 'then': convert(value, 'date')},
            {'case': {'$gt': ['$$epoch', 253_402_300_799_999]}, 'then': None},
            {'case': {'$gte': ['$$epoch', 100_000_000_000]}, 'then': convert(convert('$$epoch', 'long'), 'date')},
            {'case': {'$gte': ['$$epoch', 1_000_000_000]},
             'then': convert(convert({'$multiply': ['$$epoch', 1000]}, 'long'), 'date')},
        ],
        'default': None,
    }}}}


def log_fields():
    return [{'$project': {
        'raw': '$$ROOT', 'timestamp': 1, 'source': 1, 'level': 1, 'message': 1,
        'source_ip': '$attributes.source_ip', 'destination_ip': '$attributes.destination_ip',
        'source_port': '$attributes.source_port', 'protocol': '$attributes.protocol',
        'destination_port': {'$ifNull': ['$attributes.destination_port', '$attributes.port', None]},
    }}, {'$unset': 'raw._search_index'}]


def lookup(collection, alias):
    return {'$lookup': {'from': collection, 'localField': '_id', 'foreignField': '_id', 'as': alias}}


def list_records(database, filters):
    logs = filters.kind == 'logs'
    collection = database[COLLECTION if logs else 'dataset_records']
    dates = {operator: value for operator, value in (('$gte', filters.start), ('$lt', filters.end)) if value is not None}
    date_match = [{'$match': {'timestamp': dates}}] if dates else []
    pipeline = (date_match + log_fields()) if logs else (dataset_fields() + date_match)
    protocol = {'$toUpper': {'$ifNull': [convert('$protocol', 'string'), '']}}
    pipeline.append({'$set': {
        'source_port': convert('$source_port', 'int'), 'destination_port': convert('$destination_port', 'int'),
        'protocol': {'$switch': {'branches': [
            {'case': {'$eq': [protocol, code]}, 'then': name}
            for code, name in [('6', 'TCP'), ('17', 'UDP'), ('1', 'ICMP'), ('', None)]
        ], 'default': protocol}},
    }})
    criteria = {key: getattr(filters, key) for key in ('source_ip', 'destination_ip', 'source_port',
                                                       'destination_port', 'protocol', 'level')
                if getattr(filters, key) is not None}
    if filters.q.strip():
        literal = {'$regex': re.escape(filters.q.strip()), '$options': 'i'}
        fields = ('_id', 'source', 'message', 'level', 'source_ip', 'destination_ip', 'protocol', 'label',
                  'timestamp', 'source_port', 'destination_port')
        pipeline.append({'$set': {'search_fields': [convert('$' + key, 'string') for key in fields]}})
        criteria['search_fields'] = literal
    if criteria:
        pipeline.append({'$match': criteria})
    if filters.risk:
        if logs and filters.risk != 'unscored':
            return {'items': [], 'total': 0, 'limit': filters.limit, 'offset': filters.offset}
        if not logs:
            pipeline.append(lookup('ml_predictions', 'prediction'))
            band = RISK_BANDS.get(filters.risk)
            predicate = {'$elemMatch': {'attack_probability': band}} if band else {
                '$not': {'$elemMatch': {'attack_probability': {'$gte': 0, '$lte': 1}}}}
            pipeline.append({'$match': {'prediction': predicate}})

    count = next(collection.aggregate([*pipeline, {'$count': 'total'}], maxTimeMS=TIMEOUT_MS), {'total': 0})
    rows_pipeline = [*pipeline, {'$sort': {'timestamp': -1, '_id': -1}},
                     {'$skip': filters.offset}, {'$limit': filters.limit}]
    if not logs:
        rows_pipeline.append(lookup('normal_records', 'normalized'))
        if not filters.risk:
            rows_pipeline.append(lookup('ml_predictions', 'prediction'))
    rows = collection.aggregate(rows_pipeline, maxTimeMS=TIMEOUT_MS, allowDiskUse=True)
    return {'items': [public_record(row) for row in rows], **count, 'limit': filters.limit, 'offset': filters.offset}


def public_record(row):
    output = {key: row.get(key) for key in ('timestamp', 'source', 'level', 'message', 'source_ip',
                                            'destination_ip', 'source_port', 'destination_port', 'protocol', 'raw')}
    prediction = next(iter(row.get('prediction', [])), {})
    probability = prediction.get('attack_probability')
    risk = None
    if isinstance(probability, (int, float)) and 0 <= probability <= 1:
        severity = next(name for name, band in reversed(RISK_BANDS.items()) if probability >= band['$gte'])
        risk = {'attack_probability': probability, 'severity': severity,
                'predicted_at': prediction.get('predicted_at')}
    return {**output, 'id': str(row['_id']), 'normalized': next(iter(row.get('normalized', [])), None), 'risk': risk}
