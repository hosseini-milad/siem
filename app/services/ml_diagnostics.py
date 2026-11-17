"""Read-only aggregates for the stored model input; never return individual records."""
import math


def label_projection():
    return {'label': {'$cond': [
        {'$and': [{'$isNumber': '$Label'}, {'$in': ['$Label', [0, 1]]}]}, '$Label', 'invalid']},
        'label_type': {'$type': '$Label'}}


def label_groups():
    return [{'$group': {'_id': {'label': '$label', 'type': '$label_type'}, 'count': {'$sum': 1}}},
            {'$sort': {'_id.label': 1, '_id.type': 1}}]


def data_diagnostics(db, sample_size=20000, full_label_counts=False, max_time_ms=30000):
    excluded = ['_id', 'original_id', 'Label', 'block_index']
    fields = [
        {'$unwind': '$fields'},
        {'$match': {'fields.k': {'$nin': excluded}}},
        {'$project': {'label': 1, 'field': '$fields.k', 'numeric': {'$isNumber': '$fields.v'},
                      'value': {'$convert': {'input': '$fields.v', 'to': 'double',
                                             'onError': None, 'onNull': None}}}},
        {'$set': {'finite': {'$and': ['$numeric', {'$ne': ['$value', None]},
                    {'$not': [{'$in': [{'$toString': '$value'}, ['NaN', 'Infinity', '-Infinity']]}]}]}}},
        {'$set': {'finite_value': {'$cond': ['$finite', '$value', None]}}},
        {'$group': {'_id': {'field': '$field', 'label': '$label'}, 'samples': {'$sum': 1},
                    'numeric': {'$sum': {'$cond': ['$numeric', 1, 0]}},
                    'finite': {'$sum': {'$cond': ['$finite', 1, 0]}},
                    'min': {'$min': '$finite_value'}, 'max': {'$max': '$finite_value'},
                    'stddev': {'$stdDevPop': '$finite_value'},
                    'zeros': {'$sum': {'$cond': [{'$and': ['$finite', {'$eq': ['$value', 0]}]}, 1, 0]}},
                    'ones': {'$sum': {'$cond': [{'$and': ['$finite', {'$eq': ['$value', 1]}]}, 1, 0]}},
                    'outside_unit_range': {'$sum': {'$cond': [{'$and': ['$finite', {'$or': [
                        {'$lt': ['$value', 0]}, {'$gt': ['$value', 1]}]}]}, 1, 0]}}}},
        {'$sort': {'_id.field': 1, '_id.label': 1}},
    ]
    pipeline = [{'$sample': {'size': sample_size}},
                {'$project': {**label_projection(), 'fields': {'$objectToArray': '$$ROOT'}}},
                {'$facet': {'labels': label_groups(), 'features': fields}}]
    result = next(db.standard_records.aggregate(pipeline, allowDiskUse=True, maxTimeMS=max_time_ms))
    sample_labels = [{'label': row['_id']['label'], 'type': row['_id']['type'], 'count': row['count']}
                     for row in result['labels']]
    counts = {}
    for row in sample_labels:
        counts[row['label']] = counts.get(row['label'], 0) + row['count']
    features = []
    for row in result['features']:
        identity = row.pop('_id')
        for name in ('min', 'max', 'stddev'):
            if isinstance(row[name], float) and not math.isfinite(row[name]):
                row[name] = None
        features.append({'field': identity['field'], 'label': identity['label'], **row,
                         'missing': counts[identity['label']] - row['samples'],
                         'non_numeric': row['samples'] - row['numeric'],
                         'non_finite': row['numeric'] - row['finite'],
                         'constant_in_sample': row['finite'] > 0 and row['min'] == row['max']})
    # Include columns that are completely absent in one sampled class.
    existing = {(row['field'], row['label']) for row in features}
    for field in sorted({row['field'] for row in features}):
        for label, count in counts.items():
            if (field, label) not in existing:
                features.append({'field': field, 'label': label, 'samples': 0,
                                 'numeric': 0, 'finite': 0, 'min': None, 'max': None, 'stddev': None,
                                 'zeros': 0, 'ones': 0, 'outside_unit_range': 0, 'missing': count,
                                 'non_numeric': 0, 'non_finite': 0, 'constant_in_sample': False})
    features.sort(key=lambda row: (row['field'], str(row['label'])))
    response = {'collection': 'standard_records', 'total_estimate': db.standard_records.estimated_document_count(),
                'requested_sample_size': sample_size, 'sampled_records': sum(counts.values()),
                'label_distribution_scope': 'sample', 'label_distribution': sample_labels,
                'sample_label_distribution': sample_labels, 'features': features,
                'excluded_fields': excluded, 'read_only': True}
    if full_label_counts:
        rows = db.standard_records.aggregate([{'$project': label_projection()}, *label_groups()],
                                             allowDiskUse=True, maxTimeMS=max_time_ms)
        response['label_distribution'] = [{'label': row['_id']['label'], 'type': row['_id']['type'],
                                           'count': row['count']} for row in rows]
        response['label_distribution_scope'] = 'full_collection'
    return response
