"""Read raw records alongside the processing results linked to their original IDs."""
from datetime import timedelta, timezone
from ipaddress import ip_address
import math
import re

from app.models.log import COLLECTION, public_document
from app.services.web_access import RECORDS as WEB_RECORDS
from app.services.agent_ingestion import AGENT_LOGS
from app.services.system_log_ml import AGENT_LOG_LABELS

TIMEOUT_MS = 30_000
MAX_CANDIDATES = 1_000
DATASET_ORDER = [('Timestamp', -1), ('_id', -1)]
LOG_ORDER = [('timestamp', -1), ('_id', -1)]
DATASET_IP_COLUMNS = {
    'source_ip': ('Src IP', 'Source IP', ' Src IP '),
    'destination_ip': ('Dst IP', 'Destination IP', ' Dst IP '),
}
RISK_BANDS = {
    'benign': {'$eq': 0},
    'low': {'$gt': 0, '$lt': .35},
    'medium': {'$gte': .35, '$lt': .65},
    'high': {'$gte': .65, '$lt': .85},
    'critical': {'$gte': .85, '$lt': 1},
    'attack': {'$eq': 1},
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


def indexed_dataset_window(start, end):
    """Prune by the stored Timestamp before interpreting the CSV row."""
    if start is None or end is None:
        return []
    lower, upper = start.timestamp(), end.timestamp()
    # Lexical ranges are valid for contemporary fixed-width epoch strings.
    if not 1_000_000_000 <= lower < upper < 10_000_000_000:
        return []
    candidates = [{'Timestamp': None}, {'Timestamp': {'$gte': start, '$lt': end}}]
    for scale in (1, 1000):
        first, last = lower * scale, upper * scale
        candidates.extend([
            {'Timestamp': {'$gte': math.floor(first), '$lt': math.ceil(last)}},
            {'Timestamp': {'$gte': str(math.floor(first)), '$lt': str(math.ceil(last))}},
        ])
    # ISO strings may carry a timezone offset. The exact parsed filter below
    # removes adjacent dates admitted here to accommodate that offset.
    first_day = start.astimezone(timezone.utc).date() - timedelta(days=1)
    after_last_day = end.astimezone(timezone.utc).date() + timedelta(days=2)
    candidates.append({'Timestamp': {'$gte': first_day.isoformat(), '$lt': after_last_day.isoformat()}})
    return [{'$match': {'$or': candidates}}]


def is_ip_address(value):
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def dataset_ip_match(filters, query_ip):
    def matches(columns, address):
        return {'$or': [{column: address} for column in columns]}

    clauses = [matches(columns, getattr(filters, key)) for key, columns in DATASET_IP_COLUMNS.items()
               if getattr(filters, key) is not None]
    if query_ip:
        columns = (*DATASET_IP_COLUMNS['source_ip'], *DATASET_IP_COLUMNS['destination_ip'])
        clauses.append(matches(columns, query_ip))
    return [{'$match': {'$and': clauses}}] if clauses else []


def log_fields():
    return [{'$project': {
        'raw': '$$ROOT', 'timestamp': 1, 'source': 1, 'level': 1, 'message': 1,
        'source_ip': '$attributes.source_ip', 'destination_ip': '$attributes.destination_ip',
        'source_port': '$attributes.source_port', 'protocol': '$attributes.protocol',
        'destination_port': {'$ifNull': ['$attributes.destination_port', '$attributes.port', None]},
    }}, {'$unset': 'raw._search_index'}]


def label_score(source):
    text = {'$toLower': {'$trim': {'input': {'$ifNull': [convert({'$arrayElemAt': [source, 0]}, 'string'), '']}}}}
    return {'$let': {'vars': {'score': convert(text, 'double')}, 'in': {'$cond': [
        {'$and': [{'$gte': ['$$score', 0]}, {'$lte': ['$$score', 1]}]}, '$$score', None,
    ]}}}


def lookup(collection, alias, pipeline=None):
    return {'$lookup': {'from': collection, 'localField': '_id', 'foreignField': 'original_id',
                        'as': alias, **({'pipeline': pipeline} if pipeline else {})}}


def final_score_stages():
    return [lookup('standard_records', 'final_label', [{'$project': {'Label': 1}}]),
            {'$set': {'risk_score': label_score('$final_label.Label')}}]


def list_records(database, filters):
    logs = filters.kind == 'logs'
    collection = database[COLLECTION if logs else 'dataset_records']
    dates = {operator: value for operator, value in (('$gte', filters.start), ('$lt', filters.end)) if value is not None}
    date_match = [{'$match': {'timestamp': dates}}] if dates else []
    query = filters.q.strip()
    query_ip = query if not logs and is_ip_address(query) else None
    order = LOG_ORDER if logs else DATASET_ORDER
    candidate_limit = [{'$sort': dict(order)}, {'$limit': MAX_CANDIDATES}]
    if logs:
        pipeline = date_match + candidate_limit + log_fields()
    else:
        candidates = indexed_dataset_window(filters.start, filters.end)
        pipeline = candidates + dataset_ip_match(filters, query_ip) + candidate_limit + dataset_fields() + date_match
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
                if getattr(filters, key) is not None and (logs or key not in DATASET_IP_COLUMNS)}
    if query and not query_ip:
        literal = {'$regex': re.escape(query), '$options': 'i'}
        fields = ('_id', 'source', 'message', 'level', 'source_ip', 'destination_ip', 'protocol', 'label',
                  'timestamp', 'source_port', 'destination_port')
        pipeline.append({'$set': {'search_fields': [convert('$' + key, 'string') for key in fields]}})
        criteria['search_fields'] = literal
    if criteria:
        pipeline.append({'$match': criteria})
    if filters.risk:
        if not logs:
            pipeline.extend(final_score_stages())
        pipeline.append({'$match': {'risk_score': RISK_BANDS.get(filters.risk)}})

    count = next(collection.aggregate([*pipeline, {'$count': 'total'}], maxTimeMS=TIMEOUT_MS), {'total': 0})
    rows_pipeline = [*pipeline, {'$sort': {'timestamp': -1, '_id': -1}},
                     {'$skip': filters.offset}, {'$limit': filters.limit}]
    if not logs:
        rows_pipeline.extend([lookup('normal_records', 'normalized'), lookup('standard_records', 'standardized')])
        if not filters.risk:
            rows_pipeline.append({'$set': {'risk_score': label_score('$standardized.Label')}})
    rows = collection.aggregate(rows_pipeline, maxTimeMS=TIMEOUT_MS, allowDiskUse=True)
    return {'items': [public_record(row) for row in rows], **count, 'limit': filters.limit, 'offset': filters.offset}


def public_record(row):
    output = {key: row.get(key) for key in ('timestamp', 'source', 'level', 'message', 'source_ip',
                                            'destination_ip', 'source_port', 'destination_port', 'protocol', 'raw')}
    score = row.get('risk_score')
    risk = None
    if score is not None:
        if score == 0:
            severity = 'benign'
        elif score == 1:
            severity = 'attack'
        else:
            severity = next(name for name in ('critical', 'high', 'medium', 'low')
                            if score >= RISK_BANDS[name].get('$gte', 0))
        risk = {'score': score, 'severity': severity}
    return {**output, 'id': str(row['_id']), 'normalized': next(iter(row.get('normalized', [])), None),
            'standardized': next(iter(row.get('standardized', [])), None), 'risk': risk}


def list_system_records(database, start, end, query, label, limit, offset):
    filters = {}
    dates = {op: value for op, value in (('$gte', start), ('$lt', end)) if value is not None}
    if dates:
        filters['timestamp'] = dates
    if query:
        filters['$or'] = [{'_id': query}, {'agent_id': query}]
    if label is not None:
        filters['predicted_label'] = label
    collection = database[AGENT_LOG_LABELS]
    total = collection.count_documents(filters, maxTimeMS=TIMEOUT_MS)
    with collection.find(filters).sort(LOG_ORDER).skip(offset).limit(limit).max_time_ms(TIMEOUT_MS) as cursor:
        items = list(cursor)
    raw = {row['_id']: row for row in database[AGENT_LOGS].find(
        {'_id': {'$in': [row['_id'] for row in items]}}).max_time_ms(TIMEOUT_MS)}
    for row in items:
        row['id'] = row.pop('_id')
        row['raw'] = raw.get(row['id'])
        row['event_id'] = (row['raw'] or {}).get('event_id')
    return {'items': items, 'total': total, 'limit': limit, 'offset': offset}


def list_web_records(database, filters):
    query = {key: value for key in ('service', 'request_id', 'method', 'status', 'source_ip')
             if (value := getattr(filters, key)) is not None}
    dates = {op: value for op, value in (('$gte', filters.start), ('$lt', filters.end)) if value is not None}
    if dates:
        query['timestamp'] = dates
    if filters.route:
        query['route'] = {'$regex': '^' + re.escape(filters.route)}
    for key, value in (('duration_ms', filters.min_duration_ms), ('response_bytes', filters.min_response_bytes)):
        if value is not None:
            query[key] = {'$gte': value}
    collection = database[WEB_RECORDS]
    total = collection.count_documents(query, maxTimeMS=TIMEOUT_MS)
    with collection.find(query).sort(LOG_ORDER).skip(filters.offset).limit(filters.limit).max_time_ms(TIMEOUT_MS) as cursor:
        items = [public_document(row) for row in cursor]
    return {'items': items, 'total': total, 'limit': filters.limit, 'offset': filters.offset}
