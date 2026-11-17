"""Offline contextual features over deterministic, non-overlapping record blocks."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import logging
import math
from statistics import mean, pstdev

from pymongo import ReplaceOne

BLOCK_SIZE = 10000
FEATURE_VERSION = 2
BOUNDED_FEATURES = {'source_record_share', 'source_ip_available',
                    'destination_ip_available', 'timestamp_available'}
logger = logging.getLogger('uvicorn.error.siem.standardization')


def raw_fields(row):
    return {key.strip().casefold(): value for key, value in row.items()}


def text(row, *names):
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip().casefold() not in {'', 'nan', 'none', 'null'}:
            return str(value).strip()
    return None


def numeric(row, *names):
    value = text(row, *names)
    try:
        value = float(value)
        return value if math.isfinite(value) else None
    except (ValueError, TypeError):
        return None


def block_features(originals):
    rows = [raw_fields(row) for row in originals]
    sources = [text(row, 'src ip', 'source ip') for row in rows]
    destinations = [text(row, 'dst ip', 'destination ip') for row in rows]
    times = [numeric(row, 'timestamp') for row in rows]
    source_count, destination_count, pairs = Counter(), Counter(), Counter()
    destinations_by_source, ports_by_source, sources_by_destination = (defaultdict(set) for _ in range(3))
    source_times = defaultdict(list)
    source_bytes, source_packets = Counter(), Counter()
    byte_samples, packet_samples = Counter(), Counter()
    for row, src, dst, timestamp in zip(rows, sources, destinations, times):
        if dst is not None:
            destination_count[dst] += 1
        if src is None:
            continue
        source_count[src] += 1
        if dst is not None:
            pairs[src, dst] += 1
            destinations_by_source[src].add(dst)
            sources_by_destination[dst].add(src)
        port = text(row, 'dst port', 'destination port')
        if port is not None:
            ports_by_source[src].add(port)
        if timestamp is not None:
            source_times[src].append(timestamp)
        for counters, samples, aliases in (
            (source_bytes, byte_samples, (('totlen fwd pkts', 'total length of fwd packets'),
                                          ('totlen bwd pkts', 'total length of bwd packets'))),
            (source_packets, packet_samples, (('tot fwd pkts', 'total fwd packets'),
                                              ('tot bwd pkts', 'total backward packets'))),
        ):
            values = [numeric(row, *names) for names in aliases]
            if all(value is not None and value >= 0 for value in values):
                counters[src] += sum(values)
                samples[src] += 1
    gaps = {}
    for src, timestamps in source_times.items():
        ordered = sorted(timestamps)
        differences = [b - a for a, b in zip(ordered, ordered[1:])]
        gaps[src] = (mean(differences), pstdev(differences)) if differences else (0.0, 0.0)
    valid_times = [value for value in times if value is not None]
    span = max(valid_times) - min(valid_times) if valid_times else 0.0
    features = []
    for src, dst, timestamp in zip(sources, destinations, times):
        gap_mean, gap_std = gaps.get(src, (0.0, 0.0))
        features.append({
            'block_size': len(rows), 'block_duration_seconds': span,
            'block_timestamp_samples': len(valid_times),
            'source_ip_available': int(src is not None),
            'destination_ip_available': int(dst is not None),
            'timestamp_available': int(timestamp is not None),
            'source_record_count': source_count[src],
            'source_record_share': source_count[src] / len(rows),
            'destination_record_count': destination_count[dst],
            'source_destination_record_count': pairs[src, dst],
            'source_unique_destination_count': len(destinations_by_source.get(src, ())),
            'source_unique_destination_port_count': len(ports_by_source.get(src, ())),
            'destination_unique_source_count': len(sources_by_destination.get(dst, ())),
            'source_timestamp_samples': len(source_times.get(src, ())),
            'source_interarrival_mean_seconds': gap_mean,
            'source_interarrival_std_seconds': gap_std,
            'source_total_bytes': source_bytes[src], 'source_byte_samples': byte_samples[src],
            'source_total_packets': source_packets[src], 'source_packet_samples': packet_samples[src],
        })
    return features


def feature_blocks(db):
    """Re-read a stable input with bounded memory for fit and transform."""
    def enrich(block, index):
        originals = {}
        for offset in range(0, len(block), 500):
            ids = [row['original_id'] for row in block[offset:offset + 500]]
            originals.update((row['_id'], row) for row in db.dataset_records.find({'_id': {'$in': ids}}))
        if any(row['original_id'] not in originals for row in block):
            raise ValueError('An original dataset_records document is missing; no features written for this block')
        features = block_features([originals[row['original_id']] for row in block])
        for row, feature in zip(block, features):
            feature['block_index'] = index
            if set(row) & (set(feature) | {'behavior_features'}):
                raise ValueError('Input contains a reserved behavioral feature name; source fields must not be overwritten')
            if any(not math.isfinite(value) for value in feature.values()):
                raise ValueError('Nonfinite behavioral feature; check source time and volume values')
        return block, features

    block = []
    index = 0
    for row in db.normal_records.find().sort('_id', 1).batch_size(500):
        block.append(row)
        if len(block) == BLOCK_SIZE:
            yield enrich(block, index)
            index += 1
            block = []
    if block:
        yield enrich(block, index)


def scale_features(features, bounds):
    result = {}
    if set(features) != set(bounds):
        raise ValueError('Saved behavioral scaling schema does not match current features')
    for name, value in features.items():
        if not math.isfinite(value):
            raise ValueError('Nonfinite behavioral feature')
        low, high = bounds[name]['min'], bounds[name]['max']
        # Preserve flags and natural proportions; other features follow frozen Min-Max.
        scaled = value if name in BOUNDED_FEATURES else ((value - low) / (high - low) if high != low else 0.0)
        if not math.isfinite(scaled):
            raise ValueError('Nonfinite scaled behavioral feature')
        result[name] = max(0.0, min(1.0, scaled))
    return result


def standardize(db, job_id):
    processed = blocks = 0
    jobs = db.standardization_runs
    try:
        db.standard_records.create_index('original_id', unique=True)
        jobs.update_one({'_id': job_id}, {'$set': {
            'phase': 'fit', 'started_at': datetime.now(timezone.utc),
            'total_estimate': db.normal_records.estimated_document_count(),
            'block_size': BLOCK_SIZE, 'order': '_id ascending', 'feature_version': FEATURE_VERSION}})
        parameters = db.standardization_parameters.find_one({'_id': 'default'})
        if parameters is None:
            bounds = {}
            scanned = 0
            for block, features in feature_blocks(db):
                for feature in features:
                    for name, value in feature.items():
                        stat = bounds.setdefault(name, {'min': value, 'max': value})
                        stat['min'] = min(stat['min'], value)
                        stat['max'] = max(stat['max'], value)
                scanned += len(block)
                jobs.update_one({'_id': job_id}, {'$set': {
                    'scanned': scanned, 'heartbeat_at': datetime.now(timezone.utc)}})
            if bounds:  # An empty run must not freeze an empty schema.
                db.standardization_parameters.update_one({'_id': 'default'}, {'$setOnInsert': {
                    'bounds': bounds, 'feature_version': FEATURE_VERSION,
                    'created_at': datetime.now(timezone.utc)}}, upsert=True)
                parameters = db.standardization_parameters.find_one({'_id': 'default'})
        if parameters is not None and parameters['feature_version'] != FEATURE_VERSION:
            raise ValueError('Unsupported saved behavioral feature version')
        bounds = parameters['bounds'] if parameters is not None else {}
        jobs.update_one({'_id': job_id}, {'$set': {
            'phase': 'transform', 'scaling_bounds': bounds, 'scanned': 0}})
        for block, features in feature_blocks(db):
            scaled = [scale_features(feature, bounds) for feature in features]
            for offset in range(0, len(block), 500):
                operations = [ReplaceOne({'_id': row['_id']}, {**row, **feature}, upsert=True)
                              for row, feature in zip(block[offset:offset + 500], scaled[offset:offset + 500])]
                db.standard_records.bulk_write(operations)
                processed += len(operations)
            blocks += 1
            jobs.update_one({'_id': job_id}, {'$set': {
                'processed': processed, 'scanned': processed, 'blocks': blocks,
                'heartbeat_at': datetime.now(timezone.utc)}})
            logger.info('Standardization %s processed=%s blocks=%s', job_id, processed, blocks)
        jobs.update_one({'_id': job_id}, {'$set': {
            'status': 'completed', 'phase': 'done', 'processed': processed,
            'blocks': blocks, 'finished_at': datetime.now(timezone.utc)}})
    except Exception as exc:
        logger.exception('Standardization %s failed', job_id)
        message = str(exc) if isinstance(exc, (ValueError, KeyError)) else 'Standardization failed; see console traceback'
        try:
            jobs.update_one({'_id': job_id}, {'$set': {
                'status': 'failed', 'error': message[:500], 'error_type': type(exc).__name__,
                'processed': processed, 'blocks': blocks, 'finished_at': datetime.now(timezone.utc)}})
        except Exception:
            logger.exception('Standardization %s could not persist failure status', job_id)
