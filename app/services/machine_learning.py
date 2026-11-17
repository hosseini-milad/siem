"""CPU LightGBM over stored standard features with diagnostic model acceptance."""
from datetime import datetime, timezone
from decimal import Decimal
from ipaddress import ip_address
import json
import logging
import math
import os
import random
from pathlib import Path
from threading import Lock
from time import perf_counter
from tempfile import TemporaryDirectory

from catboost import CatBoostClassifier
import lightgbm as lgb
import numpy as np
from scipy.special import expit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss, confusion_matrix,
                             precision_score, recall_score, roc_auc_score, f1_score, log_loss)

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
        self.threads = threads
        self.booster = lgb.Booster(model_str=artifact['booster'])
        self.catboost = CatBoostClassifier(thread_count=threads)
        with TemporaryDirectory(prefix='siem-cat-load-') as temporary:
            path = Path(temporary) / 'model.json'
            path.write_text(json.dumps(artifact['catboost']), encoding='utf-8')
            self.catboost.load_model(str(path), format='json')
        self.lock = Lock()  # Avoid concurrent native calls and unbounded CPU oversubscription.

    def raw_scores(self, matrix):
        with self.lock:
            light = self.booster.predict(matrix, raw_score=True, num_threads=self.threads)
            cat = np.asarray(self.catboost.predict(matrix, prediction_type='RawFormulaVal',
                                                  thread_count=self.threads)).reshape(-1)
        weight = self.artifact['ensemble']['lightgbm_weight']
        combined = np.clip(weight * expit(light) + (1 - weight) * expit(cat), 1e-12, 1 - 1e-12)
        return {'lightgbm': light, 'catboost': cat, 'ensemble': np.log(combined / (1 - combined))}

    def probabilities(self, matrix):
        margins = self.raw_scores(matrix)['ensemble']
        return apply_calibration(margins, self.artifact['calibration'])

    def predict(self, records=None, matrix=None, raw=False):
        start = perf_counter()
        ids = None
        if records is not None:
            ids = [row.get('original_id', row.get('_id')) for row in records]
            if raw:
                if not self.artifact.get('normalization_schema') or not self.artifact.get('behavior_bounds'):
                    raise ValueError('Raw preprocessing snapshot is unavailable; send standard records or a prepared matrix')
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
        return {'count': len(items), 'items': items,
                'timing_ms': {'prepare': (prepared - start) * 1000,
                              'inference': (predicted - prepared) * 1000,
                              'service_total': (perf_counter() - start) * 1000}}


class ModelManager:
    def __init__(self, directory, threads):
        self.directory = Path(directory)
        self.threads = threads
        self.active = None
        self.training_lock = Lock()
        self.state_lock = Lock()
        path = self.directory / 'active.json'
        if path.exists():
            artifact = json.loads(path.read_text())
            if 'catboost' in artifact:  # Old LightGBM-only files are not served or migrated.
                self.active = Predictor(artifact, threads)

    def require(self):
        predictor = self.active  # Each request retains its snapshot during a model swap.
        if predictor is None:
            raise LookupError('No trained model is active')
        metrics = predictor.artifact.get('test_metrics', {})
        matrix = metrics.get('confusion_matrix')
        rejected = predictor.artifact.get('acceptance', {}).get('accepted') is False
        if matrix is not None and sum(map(sum, matrix)) > 0:
            rejected = rejected or (matrix[0][0] + matrix[1][0] == 0 or matrix[0][1] + matrix[1][1] == 0)
        if rejected or metrics.get('roc_auc', 1) <= 0.5:
            raise LookupError('Active model failed discrimination checks; retrain before predicting')
        return predictor

    def clear(self):
        with self.state_lock:
            self.active = None
            (self.directory / 'active.json').unlink(missing_ok=True)
            (self.directory / 'active.tmp').unlink(missing_ok=True)

    def publish(self, artifact):
        predictor = Predictor(artifact, self.threads)
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.directory / 'active.tmp'
        try:
            temporary.write_text(json.dumps(artifact, allow_nan=False))
            os.replace(temporary, self.directory / 'active.json')
        finally:
            temporary.unlink(missing_ok=True)
        with self.state_lock:
            self.active = predictor


def coverage_requirements(counts, budget):
    """Minimum stratum quotas needed to cover both labels in four disjoint splits."""
    mixed = min(4, counts['mixed'])
    requirements = {'mixed': mixed, 'benign': 4 - mixed, 'attack': 4 - mixed}
    description = ', '.join(f'{name}={counts[name]}' for name in ('benign', 'attack', 'mixed'))
    if any(counts[name] < value for name, value in requirements.items()):
        raise ValueError('Insufficient independent blocks for both classes in train, validation, calibration and test: '
                         + description + '. Each class must occur in at least 4 distinct complete blocks; '
                         'add labelled blocks or complete normalization/standardization. Do not duplicate records.')
    minimum = sum(requirements.values())
    if budget < minimum:
        raise ValueError(f'Block-separated evaluation needs at least {minimum * BLOCK_SIZE} records '
                         f'for this class distribution ({description}); increase max_records to '
                         f'{minimum * BLOCK_SIZE} or more.')
    return requirements


def block_kind(labels):
    classes = set(labels)
    return 'mixed' if classes == {0, 1} else ('attack' if classes == {1} else 'benign')


def training_blocks(db, max_records, diagnostics=None, progress=None):
    """Scan all block labels; bound retained raw rows, not the scan's prefix."""
    diagnostics = diagnostics if diagnostics is not None else {}
    budget = max_records // BLOCK_SIZE
    rng = random.Random(42)
    counts = dict.fromkeys(('benign', 'attack', 'mixed'), 0)
    reservoirs = {name: [] for name in counts}
    references = []
    scanned = 0
    reported = perf_counter()
    for row in db.standard_records.find({}, {'original_id': 1, 'Label': 1}).sort('_id', 1).batch_size(500):
        references.append(row)
        if len(references) != BLOCK_SIZE:
            continue
        if any('Label' not in item for item in references):
            raise ValueError('standard_records must contain Label; rerun standardization before training')
        labelled = references
        kind = block_kind(label_value(item) for item in labelled)
        candidate = {'index': scanned, 'first': references[0]['_id'], 'last': references[-1]['_id']}
        counts[kind] += 1
        if len(reservoirs[kind]) < budget:
            reservoirs[kind].append(candidate)
        else:
            slot = rng.randrange(counts[kind])
            if slot < budget:
                reservoirs[kind][slot] = candidate
        scanned += 1
        references = []
        diagnostics.update({'complete_blocks_scanned': scanned, 'block_classes': dict(counts), 'seed': 42})
        if progress and (scanned == 1 or perf_counter() - reported >= 5):
            progress(dict(diagnostics))
            reported = perf_counter()
    diagnostics['trailing_records_ignored'] = len(references)
    if progress:
        progress(dict(diagnostics))
    if scanned < 5:
        raise ValueError(f'At least five complete 10000-record blocks (50000 records) are required; found {scanned}')
    quota = coverage_requirements(counts, budget)
    total = min(budget, scanned)
    while sum(quota.values()) < total:
        available = [name for name in counts if quota[name] < counts[name]]
        name = max(available, key=lambda name: counts[name] * total / scanned - quota[name])
        quota[name] += 1
    selected = []
    for name in counts:
        rng.shuffle(reservoirs[name])
        selected.extend(reservoirs[name][:quota[name]])
    selected.sort(key=lambda candidate: candidate['index'])
    diagnostics.update({'selected_block_classes': quota, 'selected_source_block_indices': [item['index'] for item in selected]})
    if progress:
        progress(dict(diagnostics))
    for candidate in selected:
        references = list(db.standard_records.find(
            {'_id': {'$gte': candidate['first'], '$lte': candidate['last']}},
            ).sort('_id', 1))
        if len(references) != BLOCK_SIZE:
            raise ValueError('Training membership changed while sampling; keep the dataset unchanged and retry')
        yield references


def split_blocks(blocks):
    if len(blocks) < 5:
        raise ValueError('At least five complete 10000-record blocks (50000 records) are required')
    groups = {'benign': [], 'attack': [], 'mixed': []}
    for index, block in enumerate(blocks):
        groups[block_kind(label_value(row) for row in block)].append(index)
    coverage_requirements({name: len(indices) for name, indices in groups.items()}, len(blocks))
    rng = random.Random(42)
    for indices in groups.values():
        rng.shuffle(indices)
    indices = [[], [], [], []]
    # Seed small holdouts with mixed blocks first; pure blocks require a pair per split.
    for partition in (3, 2, 1, 0):
        if groups['mixed']:
            indices[partition].append(groups['mixed'].pop())
        else:
            indices[partition].extend([groups['benign'].pop(), groups['attack'].pop()])
    desired = [len(blocks) * ratio for ratio in (0.55, 0.15, 0.15, 0.15)]
    targets = [max(1, int(value)) for value in desired]
    while sum(targets) < len(blocks):
        part = max(range(4), key=lambda index: desired[index] - targets[index])
        targets[part] += 1
    remaining = [index for group in groups.values() for index in group]
    rng.shuffle(remaining)
    for index in remaining:
        partition = max(range(4), key=lambda part: targets[part] - len(indices[part]))
        indices[partition].append(index)
    for group in indices:
        group.sort()
    return [[blocks[index] for index in group] for group in indices], indices


def train(blocks, threads, threshold=0.5, rounds=500, input_format='raw', preprocessing=None):
    partitions, partition_indices = split_blocks(blocks)
    labels = [np.asarray([label_value(row) for block in part for row in block], dtype=np.int32)
              for part in partitions]
    if input_format == 'standard':
        excluded = {'_id', 'original_id', 'Label', 'block_index'}
        names = sorted(set(partitions[0][0][0]) - excluded)
        required_behavior = set(block_features([{}])[0])
        if not required_behavior <= set(names):
            raise ValueError('standard_records is missing behavioral features; rerun standardization')
        matrices = []
        for part in partitions:
            chunks = []
            for block in part:
                if any(type(row.get('Label')) not in (int, float) or row['Label'] not in (0, 1) for row in block):
                    raise ValueError('standard_records.Label must be numeric 0 or 1')
                chunks.append(feature_matrix([{key: value for key, value in row.items() if key not in excluded}
                                              for row in block], names))
            matrices.append(np.concatenate(chunks))
        schema = (preprocessing or {}).get('normalization_schema')
        bounds = (preprocessing or {}).get('behavior_bounds')
    else:
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
    constant = np.ptp(matrices[0], axis=0) == 0
    if constant.all():
        raise TrainingRejected('All training features are constant; inspect standard_records before retraining',
                               {'feature_count': len(names), 'train_constant_features': names})
    feature_ids = [f'f{i}' for i in range(len(names))]
    training_data = lgb.Dataset(matrices[0], label=labels[0], feature_name=feature_ids)
    validation_data = lgb.Dataset(matrices[1], label=labels[1], feature_name=feature_ids, reference=training_data)
    booster = lgb.train({'objective': 'binary', 'metric': 'auc', 'verbosity': -1, 'num_threads': threads,
                         'num_leaves': 31, 'max_depth': 6, 'learning_rate': 0.05,
                         'min_data_in_leaf': 40, 'seed': 42, 'deterministic': True, 'force_col_wise': True},
                        training_data, num_boost_round=rounds, valid_sets=[validation_data],
                        callbacks=[lgb.early_stopping(50, verbose=False)])
    cat = CatBoostClassifier(iterations=rounds, depth=6, learning_rate=0.05, loss_function='Logloss',
                             eval_metric='AUC', thread_count=threads, random_seed=42,
                             allow_writing_files=False, verbose=False)
    cat.fit(matrices[0], labels[0], eval_set=(matrices[1], labels[1]),
            early_stopping_rounds=50, use_best_model=True)
    light_valid = expit(booster.predict(matrices[1], raw_score=True, num_threads=threads))
    cat_valid = cat.predict_proba(matrices[1], thread_count=threads)[:, 1]
    weight, selection_scores = choose_weight(light_valid, cat_valid, labels[1])
    with TemporaryDirectory(prefix='siem-cat-save-') as temporary:
        path = Path(temporary) / 'model.json'
        cat.save_model(str(path), format='json')
        cat_payload = json.loads(path.read_text(encoding='utf-8'))
    split_names = ('train', 'validation', 'calibration', 'test')
    artifact = {'algorithm': 'LightGBM + CatBoost',
                'created_at': datetime.now(timezone.utc).isoformat(), 'features': names,
                'input_format': input_format,
                'preprocessing_provenance': ('existing standard_records; preprocessing may have been fitted globally'
                                             if input_format == 'standard' else 'raw; train-only fit'),
                'normalization_schema': schema, 'behavior_bounds': bounds,
                'threshold': threshold, 'booster': booster.model_to_string(), 'catboost': cat_payload,
                'ensemble': {'method': 'weighted raw probabilities followed by Platt calibration',
                             'lightgbm_weight': weight, 'catboost_weight': 1 - weight,
                             'selection_metric': 'validation_log_loss', 'validation_scores': selection_scores},
                'feature_importance_gain': dict(zip(names, booster.feature_importance('gain').tolist())),
                'feature_importance_catboost': dict(zip(names, cat.get_feature_importance().tolist())),
                'split': {'order': 'deterministic class-covered whole-block split; not chronological',
                          'seed': 42, 'block_indices': dict(zip(split_names, partition_indices)),
                          'class_counts': {name: {'benign': int((y == 0).sum()), 'attack': int((y == 1).sum())}
                                           for name, y in zip(split_names, labels)},
                          **{name + '_rows': len(y) for name, y in zip(split_names, labels)}}}
    predictor = Predictor(artifact, threads)
    calibration_scores = predictor.raw_scores(matrices[2])
    calibrations = {name: fit_calibration(score, labels[2]) for name, score in calibration_scores.items()}
    artifact['calibration'] = calibrations['ensemble']
    artifact['base_calibration'] = {name: calibrations[name] for name in ('lightgbm', 'catboost')}
    test_scores = predictor.raw_scores(matrices[3])
    artifact['evaluation'] = {name: {**metric_report(labels[3], apply_calibration(score, calibrations[name]), threshold),
                                    'raw_auc': float(roc_auc_score(labels[3], score))}
                              for name, score in test_scores.items()}
    artifact['test_metrics'] = artifact['evaluation']['ensemble']
    artifact['diagnostics'] = {
        'feature_count': len(names), 'train_constant_features': [name for name, flag in zip(names, constant) if flag],
        'calibration': score_diagnostics(calibration_scores['ensemble'], labels[2], artifact),
        'test': score_diagnostics(test_scores['ensemble'], labels[3], artifact),
        'trained_trees': {'lightgbm': predictor.booster.num_trees(), 'catboost': cat.tree_count_}}
    artifact['acceptance'] = acceptance(artifact)
    return artifact


class TrainingRejected(ValueError):
    def __init__(self, message, diagnostics):
        super().__init__(message)
        self.diagnostics = diagnostics


def choose_weight(light, cat, labels):
    scores = [{'lightgbm_weight': float(weight), 'log_loss': float(log_loss(labels, weight * light + (1 - weight) * cat))}
              for weight in np.linspace(0, 1, 11)]
    best = min(scores, key=lambda row: (row['log_loss'], abs(row['lightgbm_weight'] - 0.5)))
    return best['lightgbm_weight'], scores


def fit_calibration(margins, labels):
    calibration = LogisticRegression(random_state=42).fit(margins.reshape(-1, 1), labels)
    return {'method': 'Platt', 'coefficient': float(calibration.coef_[0, 0]),
            'intercept': float(calibration.intercept_[0])}


def apply_calibration(margins, calibration):
    return expit(calibration['coefficient'] * margins + calibration['intercept'])


def metric_report(labels, probabilities, threshold):
    predictions = probabilities >= threshold
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {'precision': float(precision_score(labels, predictions, zero_division=0)),
            'recall': float(recall_score(labels, predictions, zero_division=0)),
            'f1': float(f1_score(labels, predictions, zero_division=0)),
            'accuracy': float((tn + tp) / len(labels)), 'false_positive_rate': float(fp / (tn + fp)),
            'roc_auc': float(roc_auc_score(labels, probabilities)),
            'average_precision': float(average_precision_score(labels, probabilities)),
            'brier_score': float(brier_score_loss(labels, probabilities)),
            'log_loss': float(log_loss(labels, probabilities)), 'confusion_matrix': matrix.tolist()}


def score_diagnostics(margins, labels, artifact):
    probabilities = apply_calibration(margins, artifact['calibration'])
    return {'raw_auc': float(roc_auc_score(labels, margins)), 'raw_margin_std': float(np.std(margins)),
            'raw_probability_min': float(expit(margins).min()), 'raw_probability_max': float(expit(margins).max()),
            'calibrated_auc': float(roc_auc_score(labels, probabilities)),
            'probability_min': float(probabilities.min()), 'probability_max': float(probabilities.max()),
            'predicted_attack': int((probabilities >= artifact['threshold']).sum()),
            'predicted_benign': int((probabilities < artifact['threshold']).sum())}


def acceptance(artifact):
    reasons = []
    for part, values in artifact['diagnostics'].items():
        if part not in {'calibration', 'test'}:
            continue
        if values['raw_auc'] <= 0.5 or values['calibrated_auc'] <= 0.5:
            reasons.append(f'{part}: no better-than-chance discrimination')
        if values['probability_max'] - values['probability_min'] <= 1e-6:
            reasons.append(f'{part}: constant or nearly constant probabilities')
        if values['predicted_attack'] == 0 or values['predicted_benign'] == 0:
            reasons.append(f'{part}: all records predicted as one class at the configured threshold')
    return {'accepted': not reasons, 'reasons': reasons,
            'policy': 'reject degenerate candidates; not a production accuracy guarantee'}


def training_job(db, manager, job_id, max_records, threshold, rounds):
    sampling = {}
    try:
        db.ml_training_runs.update_one({'_id': job_id}, {'$set': {'phase': 'read'}})
        def progress(details):
            db.ml_training_runs.update_one({'_id': job_id}, {'$set': {
                'sampling': details, 'heartbeat_at': datetime.now(timezone.utc)}})
        blocks = list(training_blocks(db, max_records, sampling, progress))
        db.ml_training_runs.update_one({'_id': job_id}, {'$set': {'phase': 'train', 'blocks': len(blocks)}})
        normalization = db.normalization_parameters.find_one({'_id': 'default'})
        standardization = db.standardization_parameters.find_one({'_id': 'default'})
        preprocessing = {'normalization_schema': normalization['schema'] if normalization else None,
                         'behavior_bounds': {name: value for name, value in standardization['bounds'].items()
                                             if name != 'block_index'} if standardization else None}
        artifact = train(blocks, manager.threads, threshold, rounds,
                         input_format='standard', preprocessing=preprocessing)
        artifact['sampling'] = sampling
        if not artifact['acceptance']['accepted']:
            db.ml_training_runs.update_one({'_id': job_id}, {'$set': {
                'status': 'rejected', 'phase': 'quality_gate', 'metrics': artifact['test_metrics'],
                'split': artifact['split'], 'diagnostics': artifact['diagnostics'],
                'acceptance': artifact['acceptance'], 'calibration': artifact['calibration'], 'evaluation': artifact['evaluation'],
                'ensemble': artifact['ensemble'], 'finished_at': datetime.now(timezone.utc)}})
            return
        manager.publish(artifact)
        db.ml_training_runs.update_one({'_id': job_id}, {'$set': {
            'status': 'completed', 'phase': 'done', 'metrics': artifact['test_metrics'], 'split': artifact['split'],
            'diagnostics': artifact['diagnostics'], 'acceptance': artifact['acceptance'],
            'calibration': artifact['calibration'], 'input_format': 'standard',
            'evaluation': artifact['evaluation'], 'ensemble': artifact['ensemble'],
            'finished_at': datetime.now(timezone.utc)}})
    except TrainingRejected as exc:
        db.ml_training_runs.update_one({'_id': job_id}, {'$set': {
            'status': 'rejected', 'phase': 'quality_gate', 'sampling': sampling,
            'diagnostics': exc.diagnostics, 'acceptance': {'accepted': False, 'reasons': [str(exc)]},
            'finished_at': datetime.now(timezone.utc)}})
    except Exception as exc:
        logger.exception('ML training %s failed', job_id)
        try:
            db.ml_training_runs.update_one({'_id': job_id}, {'$set': {
                'status': 'failed', 'sampling': sampling,
                'error': str(exc)[:500] if isinstance(exc, ValueError) else 'Training failed; see console traceback',
                'finished_at': datetime.now(timezone.utc)}})
        except Exception:
            logger.exception('Could not record ML training failure')
