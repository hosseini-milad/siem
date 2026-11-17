"""CPU LightGBM with train-only preprocessing and immutable inference snapshots."""
from datetime import datetime, timezone
from decimal import Decimal
from ipaddress import ip_address
import json
import logging
import math
import os
from pathlib import Path
from threading import Lock
from time import perf_counter
from uuid import uuid4

import lightgbm as lgb
import numpy as np
from scipy.special import expit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss, confusion_matrix,
                             precision_score, recall_score, roc_auc_score)

from app.services.normalization import EXCLUDED, fit_rows, label_value, transform, value_text, MISSING
from app.services.standardization import BLOCK_SIZE, BOUNDED_FEATURES, block_features, scale_features

logger = logging.getLogger('uvicorn.error.siem.ml')


def feature_matrix(rows, names):
    """Strict contract: no silent missing columns or feature-order guesses."""
    try:
        if any(set(row) != set(names) for row in rows):
            raise ValueError('Feature columns must exactly match the active model schema')
        matrix = np.asarray([[row[name] for name in names] for row in rows], dtype=np.float32)
    except (TypeError, OverflowError) as exc:
        raise ValueError('Features must be finite numeric values') from exc
    return validate_matrix(matrix, len(names))


def validate_matrix(matrix, columns):
    matrix = np.asarray(matrix, dtype=np.float32, order='C')
    if matrix.ndim != 2 or matrix.shape[1] != columns or not 1 <= len(matrix) <= BLOCK_SIZE:
        raise ValueError('Expected 1..10000 rows with exactly the model feature count')
    if not np.isfinite(matrix).all() or (matrix < 0).any() or (matrix > 1).any():
        raise ValueError('Every feature must be finite and between zero and one')
    return matrix


def prepare_raw(rows, schema, bounds=None, feature_order=None):
    """Labels never enter feature construction; each request is one complete block."""
    raw_features = block_features(rows)
    fields = {stat['field'] for stat in schema}
    for row in rows:
        extra = {key for key in row.keys() - fields if key.strip().casefold() not in EXCLUDED and key != 'Label'}
        if extra:
            raise ValueError('Raw columns do not match the trained feature schema')
    columns = {}
    for stat in schema:
        field = stat['field']
        if stat['kind'] == 'categorical':
            values = [value_text(row.get(field)) for row in rows]
            for category, output in zip(stat['categories'], stat['outputs']):
                columns[output] = np.fromiter((value == category and value.casefold() not in MISSING
                                               for value in values), dtype=np.float64)
        elif stat['kind'] == 'ip':
            values = [value_text(row.get(field)) for row in rows]
            cache = {}
            for value in set(values):
                address = ip_address(value) if value.casefold() not in MISSING else None
                cache[value] = int(address) / ((1 << address.max_prefixlen) - 1) if address else 0.0
            columns[field] = np.fromiter((cache[value] for value in values), dtype=np.float64)
        else:
            low = Decimal(stat['min']) if stat['min'] is not None else None
            high = Decimal(stat['max']) if stat['max'] is not None else None
            if low is None or high == low:
                if any(isinstance(row.get(field), (dict, list)) for row in rows):
                    raise ValueError('Expected flat CSV fields; nested input is unsupported')
                columns[field] = np.zeros(len(rows))
                continue
            low_float, high_float = float(low), float(high)
            difference = high_float - low_float
            if not math.isfinite(difference) or not math.isfinite(low_float) or difference == 0:
                # Preserve Decimal behavior for extreme or nearly equal bounds.
                columns[field] = np.fromiter((transform({'_id': 0, 'Label': 'benign', field: value},
                                                        [stat])[field] for value in
                                             (value_text(row.get(field)) for row in rows)), dtype=np.float64)
                continue
            try:
                numeric = np.asarray([row.get(field, np.nan) for row in rows], dtype=np.float64)
            except (ValueError, TypeError):
                def parse(value):
                    value = value_text(value)  # Nested values must fail, not silently disappear.
                    try:
                        return float(value)
                    except ValueError:
                        return np.nan
                numeric = np.fromiter((parse(row.get(field)) for row in rows), dtype=np.float64)
            if numeric.ndim != 1:
                raise ValueError('Expected flat CSV fields; nested input is unsupported')
            numeric[~np.isfinite(numeric)] = low_float
            with np.errstate(over='ignore'):
                columns[field] = np.clip((numeric - low_float) / difference, 0, 1)
    if columns.keys() & raw_features[0].keys():
        raise ValueError('Behavioral feature name collides with a source feature')
    behavior_names = list(raw_features[0])
    behavior_matrix = np.asarray([[feature[name] for name in behavior_names] for feature in raw_features], dtype=np.float64)
    if not np.isfinite(behavior_matrix).all():
        raise ValueError('Nonfinite behavioral feature')
    if bounds is not None:
        if set(bounds) != set(behavior_names):
            raise ValueError('Saved behavioral scaling schema does not match current features')
        lows = np.asarray([bounds[name]['min'] for name in behavior_names])
        highs = np.asarray([bounds[name]['max'] for name in behavior_names])
        denominators = highs - lows
        scaled = np.divide(behavior_matrix - lows, denominators, out=np.zeros_like(behavior_matrix),
                           where=denominators != 0)
        for index, name in enumerate(behavior_names):
            if name in BOUNDED_FEATURES:
                scaled[:, index] = behavior_matrix[:, index]
        behavior_matrix = np.clip(scaled, 0, 1)
    columns.update((name, behavior_matrix[:, index]) for index, name in enumerate(behavior_names))
    names = list(columns) if feature_order is None else feature_order
    if set(names) != set(columns):
        raise ValueError('Feature columns must exactly match the active model schema')
    matrix = np.column_stack([columns[name] for name in names])
    if feature_order is not None:
        return validate_matrix(matrix, len(names)), raw_features
    return [dict(zip(names, values.tolist())) for values in matrix], raw_features


class Predictor:
    def __init__(self, artifact, threads):
        self.artifact = artifact
        self.names = artifact['features']
        self.version = artifact['model_version']
        self.threads = threads
        self.booster = lgb.Booster(model_str=artifact['booster'])
        self.lock = Lock()  # Avoid concurrent native calls and unbounded CPU oversubscription.

    def probabilities(self, matrix):
        with self.lock:
            margins = self.booster.predict(matrix, raw_score=True, num_threads=self.threads)
        return expit(self.artifact['calibration']['coefficient'] * margins +
                     self.artifact['calibration']['intercept'])

    def predict(self, records=None, matrix=None, raw=False):
        start = perf_counter()
        ids = None
        if records is not None:
            ids = [row.get('original_id', row.get('_id')) for row in records]
            if raw:
                matrix, _ = prepare_raw(records, self.artifact['normalization_schema'],
                                         self.artifact['behavior_bounds'], feature_order=self.names)
            else:
                records = [{key: value for key, value in row.items()
                            if key not in {'_id', 'original_id', 'Label', 'block_index'}} for row in records]
            if not raw:
                matrix = feature_matrix(records, self.names)
        else:
            matrix = validate_matrix(matrix, len(self.names))
        prepared = perf_counter()
        probabilities = self.probabilities(matrix)
        predicted = perf_counter()
        threshold = self.artifact['threshold']
        items = [{'original_id': ids[i] if ids is not None else None,
                  'attack_probability': float(probability),
                  'predicted_label': int(probability >= threshold)}
                 for i, probability in enumerate(probabilities)]
        return {'model_version': self.version, 'count': len(items), 'items': items,
                'timing_ms': {'prepare': (prepared - start) * 1000,
                              'inference': (predicted - prepared) * 1000,
                              'service_total': (perf_counter() - start) * 1000}}


class ModelManager:
    def __init__(self, directory, threads):
        self.directory = Path(directory)
        self.threads = threads
        self.active = None
        self.training_lock = Lock()
        path = self.directory / 'active.json'
        if path.exists():
            self.active = Predictor(json.loads(path.read_text()), threads)

    def require(self, version=None):
        predictor = self.active  # Each request retains its snapshot during a model swap.
        if predictor is None:
            raise LookupError('No trained model is active')
        if version is not None and version != predictor.version:
            raise ValueError('model_version does not match the active model; refresh the schema')
        return predictor

    def publish(self, artifact):
        predictor = Predictor(artifact, self.threads)
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.directory / (artifact['model_version'] + '.tmp')
        try:
            temporary.write_text(json.dumps(artifact, allow_nan=False))
            os.replace(temporary, self.directory / 'active.json')
        finally:
            temporary.unlink(missing_ok=True)
        self.active = predictor


def training_blocks(db, max_records):
    """Use standard_records membership/order, but reconstruct raw data for leakage-free Fit."""
    block = []
    for row in db.standard_records.find({}, {'original_id': 1}).sort('_id', 1).limit(max_records).batch_size(500):
        block.append(row)
        if len(block) == BLOCK_SIZE:
            originals = {}
            for offset in range(0, BLOCK_SIZE, 500):
                ids = [item['original_id'] for item in block[offset:offset + 500]]
                originals.update((item['_id'], item) for item in db.dataset_records.find({'_id': {'$in': ids}}))
            if any(item['original_id'] not in originals for item in block):
                raise ValueError('A training record has no original dataset_records document')
            yield [originals[item['original_id']] for item in block]
            block = []
    # The final partial block is excluded from training to preserve complete block boundaries.


def train(blocks, threads, threshold=0.5, rounds=150):
    if len(blocks) < 5:
        raise ValueError('At least five complete 10000-record blocks (50000 records) are required')
    train_end = int(len(blocks) * 0.6)
    calibration_end = int(len(blocks) * 0.8)
    partitions = [blocks[:train_end], blocks[train_end:calibration_end], blocks[calibration_end:]]
    labels = [np.asarray([label_value(row) for block in part for row in block], dtype=np.int32)
              for part in partitions]
    if any(set(y.tolist()) != {0, 1} for y in labels):
        raise ValueError('Train, calibration and test partitions must each contain both classes; preserve block separation')
    _, schema = fit_rows(row for block in partitions[0] for row in block)
    prepared = []
    bounds = {}
    for block in partitions[0]:
        records, behavior = prepare_raw(block, schema)
        prepared.append(records)
        for feature in behavior:
            for name, value in feature.items():
                stat = bounds.setdefault(name, {'min': value, 'max': value})
                stat['min'], stat['max'] = min(stat['min'], value), max(stat['max'], value)
    # Reapply train-only behavioral scaling, leaving already-normalized original features intact.
    for records in prepared:
        for record in records:
            record.update(scale_features({name: record[name] for name in bounds}, bounds))
    names = sorted(prepared[0][0])
    matrices = [np.concatenate([feature_matrix(records, names) for records in prepared])]
    for part in partitions[1:]:
        matrices.append(np.concatenate([feature_matrix(prepare_raw(block, schema, bounds)[0], names)
                                        for block in part]))
    booster = lgb.train({'objective': 'binary', 'verbosity': -1, 'num_threads': threads,
                         'num_leaves': 31, 'max_depth': 6, 'learning_rate': 0.05,
                         'min_data_in_leaf': 40, 'seed': 42, 'deterministic': True,
                         'force_col_wise': True},
                        lgb.Dataset(matrices[0], label=labels[0],
                                    feature_name=[f'f{i}' for i in range(len(names))]),
                        num_boost_round=rounds)
    margins = booster.predict(matrices[1], raw_score=True, num_threads=threads)
    calibration = LogisticRegression(random_state=42).fit(margins.reshape(-1, 1), labels[1])
    artifact = {'model_version': uuid4().hex, 'format_version': 1, 'algorithm': 'LightGBM',
                'created_at': datetime.now(timezone.utc).isoformat(), 'features': names,
                'normalization_schema': schema, 'behavior_bounds': bounds,
                'threshold': threshold, 'booster': booster.model_to_string(),
                'calibration': {'method': 'Platt', 'coefficient': float(calibration.coef_[0, 0]),
                                'intercept': float(calibration.intercept_[0])},
                'feature_importance_gain': dict(zip(names, booster.feature_importance('gain').tolist())),
                'split': {'order': 'standard_records._id ascending; complete blocks',
                          'train_rows': len(labels[0]), 'calibration_rows': len(labels[1]),
                          'test_rows': len(labels[2])}}
    predictor = Predictor(artifact, threads)
    probabilities = predictor.probabilities(matrices[2])
    predictions = probabilities >= threshold
    artifact['test_metrics'] = {
        'precision': float(precision_score(labels[2], predictions, zero_division=0)),
        'recall': float(recall_score(labels[2], predictions, zero_division=0)),
        'roc_auc': float(roc_auc_score(labels[2], probabilities)),
        'average_precision': float(average_precision_score(labels[2], probabilities)),
        'brier_score': float(brier_score_loss(labels[2], probabilities)),
        'confusion_matrix': confusion_matrix(labels[2], predictions, labels=[0, 1]).tolist()}
    return artifact


def training_job(db, manager, job_id, max_records, threshold, rounds):
    try:
        db.ml_training_runs.update_one({'_id': job_id}, {'$set': {'phase': 'read'}})
        blocks = list(training_blocks(db, max_records))
        db.ml_training_runs.update_one({'_id': job_id}, {'$set': {'phase': 'train', 'blocks': len(blocks)}})
        artifact = train(blocks, manager.threads, threshold, rounds)
        manager.publish(artifact)
        db.ml_training_runs.update_one({'_id': job_id}, {'$set': {
            'status': 'completed', 'phase': 'done', 'model_version': artifact['model_version'],
            'metrics': artifact['test_metrics'], 'split': artifact['split'],
            'finished_at': datetime.now(timezone.utc)}})
    except Exception as exc:
        logger.exception('ML training %s failed', job_id)
        try:
            db.ml_training_runs.update_one({'_id': job_id}, {'$set': {
                'status': 'failed', 'error': str(exc)[:500] if isinstance(exc, ValueError) else 'Training failed; see console traceback',
                'finished_at': datetime.now(timezone.utc)}})
        except Exception:
            logger.exception('Could not record ML training failure')
