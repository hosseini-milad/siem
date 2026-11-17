"""Incremental normalization using a persisted, immutable feature schema."""
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address
import math
import logging
import os
from time import monotonic

from bson import BSON
from pymongo import UpdateOne

logger = logging.getLogger('uvicorn.error.siem.normalization')

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


def fit(db, progress=None):
    stats = {}
    count = 0
    reported = monotonic()
    for row in db.dataset_records.find().batch_size(500):
        label_value(row)
        count += 1
        if progress and (count == 1 or monotonic() - reported >= 5):
            progress(count)
            reported = monotonic()
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
    if progress:
        progress(count)
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
            result[field] = max(0.0, min(1.0, result[field]))
            if not math.isfinite(result[field]):
                raise ValueError('Nonfinite normalized value')
    return result


def normalize(db, job_id):
    processed = skipped = 0
    try:
        logger.info('Normalization %s started pid=%s', job_id, os.getpid())
        total = db.dataset_records.estimated_document_count()
        db.normalization_runs.update_one({'_id': job_id}, {'$set': {
            'started_at': datetime.now(timezone.utc), 'heartbeat_at': datetime.now(timezone.utc),
            'worker_pid': os.getpid(), 'total_estimate': total, 'scanned': 0}})

        def fit_progress(scanned):
            now = datetime.now(timezone.utc)
            db.normalization_runs.update_one({'_id': job_id}, {'$set': {
                'phase': 'fit', 'scanned': scanned, 'heartbeat_at': now}})
            logger.info('Normalization %s fit scanned=%s estimated_total=%s (no output until fit completes)',
                        job_id, scanned, total)

        parameters = db.normalization_parameters.find_one({'_id': 'default'})
        if parameters is None:
            # Reuse the schema that produced output from the previous release.
            previous = db.normalization_runs.find_one(
                {'status': 'completed', 'schema': {'$exists': True}}, sort=[('finished_at', -1)])
            if previous:
                schema = previous['schema']
            elif db.normal_records.estimated_document_count():
                raise ValueError('Existing normal_records has no saved schema; restore the matching completed run before continuing')
            else:
                logger.info('Normalization %s computing initial Min-Max schema', job_id)
                _, schema = fit(db, fit_progress)
            db.normalization_parameters.update_one({'_id': 'default'}, {'$setOnInsert': {
                'schema': schema, 'created_at': datetime.now(timezone.utc)}}, upsert=True)
            parameters = db.normalization_parameters.find_one({'_id': 'default'})
        schema = parameters['schema']
        logger.info('Normalization %s schema ready; preparing output index', job_id)
        db.normal_records.create_index('original_id', unique=True)
        db.normalization_runs.update_one({'_id': job_id}, {'$set': {
            'total': total, 'schema': schema, 'phase': 'transform', 'scanned': 0, 'heartbeat_at': datetime.now(timezone.utc)}})
        logger.info('Normalization %s transform started', job_id)
        reported = monotonic()

        def consume(rows):
            nonlocal processed, skipped, reported
            ids = [row['_id'] for row in rows]
            existing = {row['original_id'] for row in db.normal_records.find(
                {'original_id': {'$in': ids}}, {'original_id': 1})}
            operations = []
            fields = {stat['field'] for stat in schema}
            for row in rows:
                if row['_id'] in existing:
                    skipped += 1
                    continue
                extra = {key for key in row if key.strip().casefold() not in EXCLUDED and key != 'Label'} - fields
                if extra:
                    raise ValueError('New source columns do not match the saved normalization schema')
                document = transform(row, schema)
                operations.append(UpdateOne({'original_id': row['_id']}, {'$setOnInsert': document}, upsert=True))
            if operations:
                result = db.normal_records.bulk_write(operations)
                processed += result.upserted_count
            db.normalization_runs.update_one({'_id': job_id}, {'$set': {'processed': processed, 'skipped': skipped, 'scanned': processed + skipped, 'heartbeat_at': datetime.now(timezone.utc)}})
            if monotonic() - reported >= 5:
                logger.info('Normalization %s transform inserted=%s skipped=%s', job_id, processed, skipped)
                reported = monotonic()

        batch = []
        for row in db.dataset_records.find().batch_size(500):
            batch.append(row)
            if len(batch) == 500:
                consume(batch)
                batch = []
        if batch:
            consume(batch)
        db.normalization_runs.update_one({'_id': job_id}, {'$set': {'status': 'completed', 'phase': 'done',
            'processed': processed, 'skipped': skipped, 'heartbeat_at': datetime.now(timezone.utc), 'finished_at': datetime.now(timezone.utc)}})
        logger.info('Normalization %s completed inserted=%s skipped=%s', job_id, processed, skipped)
    except Exception as exc:
        logger.exception('Normalization %s failed inserted=%s skipped=%s', job_id, processed, skipped)
        message = str(exc) if isinstance(exc, ValueError) else 'Normalization failed; see console traceback for details'
        try:
            db.normalization_runs.update_one({'_id': job_id}, {'$set': {'status': 'failed', 'error': message[:500],
                'error_type': type(exc).__name__, 'processed': processed, 'skipped': skipped,
                'heartbeat_at': datetime.now(timezone.utc), 'finished_at': datetime.now(timezone.utc)}})
        except Exception:
            logger.exception('Normalization %s could not persist failure status; database unavailable', job_id)
