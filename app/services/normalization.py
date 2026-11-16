"""Fit on all source rows, then transform to a staging collection and publish."""
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address
import math

from bson import BSON

EXCLUDED = {'_id', 'source file', 'original_id'}
MISSING = {'', 'nan', 'inf', '+inf', '-inf', 'infinity', '-infinity', 'null', 'none'}


def value_text(value):
    if isinstance(value, (dict, list)):
        raise ValueError('Expected flat CSV fields; nested input is unsupported')
    return '' if value is None else str(value).strip()


def label_value(row):
    if 'Label' not in row:
        raise ValueError('Every source row must contain Label')
    text = value_text(row['Label']).casefold()
    if text in MISSING or text in {'unknown', 'unlabeled'}:
        raise ValueError('Missing or unknown Label; supply benign or an attack name')
    if text in {'benign', 'normal', '0'}:
        return 0
    if text == '1' or not text.replace('.', '', 1).isdigit():
        return 1
    raise ValueError('Unsupported numeric Label')


def number(text):
    if text.casefold() in MISSING:
        return None
    try:
        result = Decimal(text)
    except InvalidOperation:
        return None
    return result if result.is_finite() else None


def fit(db):
    stats = {}
    count = 0
    for row in db.dataset_records.find().batch_size(500):
        label_value(row)
        count += 1
        for field, raw in row.items():
            if field.strip().casefold() in EXCLUDED or field == 'Label':
                continue
            if field.startswith('$') or '.' in field or '\x00' in field:
                raise ValueError('Feature names cannot contain dots, NUL or start with $')
            stat = stats.setdefault(field, {'field': field, 'kind': 'numeric', 'min': None, 'max': None,
                                            'categories': set(), 'numeric_seen': False})
            text = value_text(raw)
            if text.casefold() in MISSING:
                continue
            if field.strip().casefold() in {'src ip', 'dst ip'}:
                ip_address(text)  # Invalid IPs must not silently become arbitrary categories.
                stat['kind'] = 'ip'
                continue
            if field.strip().casefold() == 'protocol':
                stat['kind'] = 'categorical'
            numeric = number(text)
            if numeric is not None and stat['kind'] != 'categorical':
                stat['numeric_seen'] = True
                stat['min'] = numeric if stat['min'] is None else min(stat['min'], numeric)
                stat['max'] = numeric if stat['max'] is None else max(stat['max'], numeric)
            else:
                stat['kind'] = 'categorical'
                stat['categories'].add(text)
                if len(stat['categories']) > 256:
                    raise ValueError(f'Too many categories in {field}; explicit encoding required')
    if not count:
        raise ValueError('dataset_records is empty')
    for stat in stats.values():
        if stat['kind'] == 'categorical' and stat['numeric_seen']:
            raise ValueError(f'Mixed numeric/text values in {stat["field"]}; clean the input first')
        stat.pop('numeric_seen')
        stat['categories'] = sorted(stat['categories'])
        for key in ('min', 'max'):
            stat[key] = str(stat[key]) if stat[key] is not None else None
    # Use generated one-hot names and reject collisions with existing column names.
    names = set(stats) | {'Label', 'original_id', '_id'}
    for stat in stats.values():
        stat['outputs'] = []
        if stat['kind'] == 'categorical':
            for index, _ in enumerate(stat['categories']):
                name = f'{stat["field"]}__category_{index}'
                if name in names:
                    raise ValueError('Generated one-hot column name collides with a source column')
                names.add(name)
                stat['outputs'].append(name)
    schema = list(stats.values())
    if len(BSON.encode({'schema': schema})) > 8 * 1024 * 1024:
        raise ValueError('Normalization schema too large')
    return count, schema


def transform(row, schema):
    result = {'_id': row['_id'], 'original_id': row['_id'], 'Label': label_value(row)}
    for stat in schema:
        field = stat['field']
        text = value_text(row.get(field))
        missing = text.casefold() in MISSING
        if stat['kind'] == 'categorical':
            for category, output in zip(stat['categories'], stat['outputs']):
                result[output] = int(not missing and text == category)
        elif stat['kind'] == 'ip':
            address = ip_address(text) if not missing else None
            result[field] = int(address) / ((1 << address.max_prefixlen) - 1) if address else 0.0
        else:
            value = number(text)
            low = Decimal(stat['min']) if stat['min'] is not None else None
            high = Decimal(stat['max']) if stat['max'] is not None else None
            result[field] = float((value - low) / (high - low)) if value is not None and low is not None and high != low else 0.0
            if not math.isfinite(result[field]) or not 0 <= result[field] <= 1:
                raise ValueError('Source changed during normalization; retry with a stable dataset')
    return result


def normalize(db, job_id):
    temporary = 'normal_staging_' + job_id.replace('-', '')
    processed = 0
    try:
        count, schema = fit(db)
        db.normalization_runs.update_one({'_id': job_id}, {'$set': {'total': count, 'schema': schema, 'phase': 'transform'}})
        collection = db[temporary]
        collection.create_index('original_id', unique=True)
        batch = []
        for row in db.dataset_records.find().batch_size(500):
            batch.append(transform(row, schema))
            if len(batch) == 500:
                collection.insert_many(batch)
                processed += len(batch)
                batch = []
                db.normalization_runs.update_one({'_id': job_id}, {'$set': {'processed': processed}})
        if batch:
            collection.insert_many(batch)
            processed += len(batch)
        if processed != count:
            raise ValueError('Source count changed during normalization')
        collection.rename('normal_records', dropTarget=True)
        db.normalization_runs.update_one({'_id': job_id}, {'$set': {'status': 'completed', 'phase': 'done',
            'processed': processed, 'finished_at': datetime.now(timezone.utc)}})
    except Exception as exc:
        message = str(exc) if isinstance(exc, ValueError) else 'Normalization failed; check database availability and server logs'
        db.normalization_runs.update_one({'_id': job_id}, {'$set': {'status': 'failed', 'error': message[:500],
            'processed': processed, 'finished_at': datetime.now(timezone.utc)}})
    finally:
        db.drop_collection(temporary)
