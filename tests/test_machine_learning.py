from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import numpy as np
import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app
from app.services.standardization import block_features

from app.services.machine_learning import (ModelManager, Predictor, feature_matrix, prepare_raw,
                                            train, training_job, validate_matrix, split_blocks, training_blocks)


def synthetic_blocks():
    return [[{'_id': f'{block:02}-{i:05}', 'original_id': f'{block:02}-{i:05}',
              'Label': 'attack' if i % 2 else 'benign', 'signal': str(i % 2),
              'Timestamp': str(block * 10000 + i), 'Src IP': f'10.0.0.{i % 10}',
              'Dst IP': f'10.1.0.{i % 7}', 'Dst Port': str(i % 3)}
             for i in range(10000)] for block in range(5)]


@pytest.fixture(scope='module')
def trained():
    blocks = synthetic_blocks()
    return train(blocks, threads=2, rounds=20), blocks


@pytest.fixture
def setup(tmp_path):
    config = Settings(mongodb_database='siem_test_' + uuid4().hex,
                      ml_model_dir=str(tmp_path / 'models'))
    mongo = MongoClient(config.mongodb_uri)
    try:
        with TestClient(create_app(config)) as client:
            yield client, mongo[config.mongodb_database], config
    finally:
        mongo.drop_database(config.mongodb_database)
        mongo.close()


def test_train_only_scaling_calibration_and_quality(trained):
    artifact, blocks = trained
    assert artifact['split']['train_rows'] == 20000
    assert artifact['split']['validation_rows'] == 10000
    assert artifact['split']['calibration_rows'] == artifact['split']['test_rows'] == 10000
    timestamp = next(stat for stat in artifact['normalization_schema'] if stat['field'] == 'Timestamp')
    train_indices = artifact['split']['block_indices']['train']
    assert timestamp['max'] == str(max(train_indices) * 10000 + 9999)
    assert set(train_indices).isdisjoint(artifact['split']['block_indices']['test'])
    assert artifact['test_metrics']['recall'] > 0.95
    assert artifact['test_metrics']['precision'] > 0.95
    assert artifact['calibration']['method'] == 'Platt'
    assert not {'Label', '_id', 'original_id', 'block_index'} & set(artifact['features'])
    assert set(artifact['feature_importance_gain']) == set(artifact['features'])
    predictor = Predictor(artifact, 2)
    raw = [{key: value for key, value in row.items() if key != 'Label'} for row in blocks[4]]
    response = predictor.predict(records=raw, raw=True)
    assert response['count'] == 10000
    assert response['items'][1]['predicted_label'] == 1
    assert response['items'][0]['original_id'] == blocks[4][0]['original_id']
    assert all(0 <= row['attack_probability'] <= 1 for row in response['items'])
    # Caller-supplied labels have no effect on prediction.
    changed = [{**row, 'Label': 'nonsense'} for row in raw]
    assert predictor.predict(records=changed, raw=True)['items'] == response['items']


def test_artifact_reload_matrix_equivalence_and_concurrent_snapshots(trained, tmp_path):
    artifact, blocks = trained
    manager = ModelManager(tmp_path, 2)
    manager.publish(artifact)
    reloaded = ModelManager(tmp_path, 2).require()
    records, _ = prepare_raw(blocks[4], artifact['normalization_schema'], artifact['behavior_bounds'])
    matrix = feature_matrix(records, artifact['features'])
    expected = reloaded.predict(matrix=matrix)['items']
    assert manager.require().predict(records=blocks[4], raw=True)['items'] == [
        {**row, 'original_id': blocks[4][i]['original_id']} for i, row in enumerate(expected)]
    with ThreadPoolExecutor(2) as executor:
        results = list(executor.map(lambda _: reloaded.predict(matrix=matrix)['items'], range(2)))
    assert results == [expected, expected]
    assert sorted(path.name for path in tmp_path.iterdir()) == ['active.json']
    manager.clear()
    assert not (tmp_path / 'active.json').exists()
    with pytest.raises(LookupError):
        manager.require()


def test_invalid_matrix_and_training_data():
    for matrix in [[[float('nan')]], [[float('inf')]], [[-1]], [[1.1]], [], [[1, 0]]]:
        with pytest.raises(ValueError):
            validate_matrix(matrix, 1)
    with pytest.raises(ValueError, match='columns'):
        feature_matrix([{'wrong': 0}], ['expected'])
    with pytest.raises(ValueError, match='five complete'):
        train([], 2)
    with pytest.raises(ValueError, match='both classes'):
        train([[{'Label': 'benign'}]] * 5, 2)


def test_inline_api_persistence_validation_and_model_schema(setup, trained):
    client, db, config = setup
    artifact, blocks = trained
    assert client.get('/api/v1/ml/model').status_code == 503
    client.app.state.ml.publish(artifact)
    metadata = client.get('/api/v1/ml/model').json()
    assert metadata['features'] == artifact['features'] and 'booster' not in metadata
    raw = [{key: value for key, value in row.items() if key != 'Label'} for row in blocks[4]]
    body = {'records': raw, 'persist': True, 'input_format': 'raw'}
    result = client.post('/api/v1/ml/predict', json=body)
    assert result.status_code == 200, result.text
    assert len(result.json()['items']) == 10000
    assert db.ml_predictions.count_documents({}) == 10000
    assert db.dataset_records.count_documents({}) == 0
    assert db.ml_predictions.find_one({'_id': raw[1]['original_id']})['predicted_label'] == 1
    assert client.post('/api/v1/ml/predict', json=body).status_code == 200
    assert db.ml_predictions.count_documents({}) == 10000
    assert client.post('/api/v1/ml/predict', json={**body, 'model_version': 'old'}).status_code == 422
    assert client.post('/api/v1/ml/predict', json={**body, 'records': []}).status_code == 422
    assert client.post('/api/v1/ml/predict', json={**body, 'records': raw + [raw[0]]}).status_code == 422
    assert client.post('/api/v1/ml/predict', json={**body, 'records': [raw[0], raw[0]]}).status_code == 422
    matrix = np.zeros((10000, len(artifact['features']))).tolist()
    assert client.post('/api/v1/ml/predict-matrix', json={
        'matrix': matrix}).status_code == 200
    assert client.post('/api/v1/ml/predict-matrix', json={
        'matrix': [[0]]}).status_code == 422


def test_database_training_and_restart(setup, trained):
    client, db, config = setup
    _, blocks = trained
    originals = [row for block in blocks for row in block]
    db.dataset_records.insert_many(originals)
    db.standard_records.insert_many([standard_row(row['_id'], int(row['Label'] == 'attack')) for row in originals])
    result = client.post('/api/v1/ml/training/runs', json={'max_records': 50000, 'rounds': 10})
    assert result.status_code == 202
    status = client.get('/api/v1/ml/training/runs/' + result.json()['id']).json()
    assert status['status'] == 'completed', status
    trained_at = client.get('/api/v1/ml/model').json()['created_at']
    assert result.json()['id'] == 'current'
    assert 'model_version' not in status
    assert db.dataset_records.find_one({'_id': originals[1]['_id']})['Label'] == 'attack'
    db.ml_training_runs.insert_one({'_id': 'interrupted', 'status': 'running'})
    with TestClient(create_app(config)) as restarted:
        assert restarted.get('/api/v1/ml/model').json()['created_at'] == trained_at
        assert db.ml_training_runs.find_one({'_id': 'interrupted'})['status'] == 'interrupted'


def test_training_failure_clears_active_model_and_unlocks(setup, trained):
    client, db, _ = setup
    artifact, _ = trained
    client.app.state.ml.publish(artifact)
    response = client.post('/api/v1/ml/training/runs', json={})
    status = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert status['status'] == 'failed'
    assert client.app.state.ml.active is None
    assert not (client.app.state.ml.directory / 'active.json').exists()
    assert not client.app.state.ml.training_lock.locked()
    assert not client.app.state.import_lock.locked()
    client.app.state.import_lock.acquire()
    try:
        assert client.post('/api/v1/ml/training/runs', json={}).status_code == 409
    finally:
        client.app.state.import_lock.release()
    assert client.get('/api/v1/ml/training/runs/' + str(uuid4())).status_code == 404


def test_vectorized_preprocessing_matches_reference_normalization():
    from app.services.normalization import fit_rows, transform
    rows = [
        {'_id': 'a', 'Label': 'benign', 'n': '-10', 'empty': '', 'constant': '5',
         'Protocol': '6', 'Src IP': '0.0.0.0'},
        {'_id': 'b', 'Label': 'attack', 'n': '10', 'empty': 'NaN', 'constant': '5',
         'Protocol': '17', 'Src IP': '255.255.255.255'},
        {'_id': 'c', 'Label': 'benign', 'n': '0', 'constant': '5', 'Protocol': '6'},
    ]
    _, schema = fit_rows(rows)
    values, _ = prepare_raw(rows, schema)
    for raw, prepared in zip(rows, values):
        reference = transform(raw, schema)
        for name, value in reference.items():
            if name not in {'_id', 'original_id', 'Label'}:
                assert prepared[name] == pytest.approx(value)
    with pytest.raises(ValueError, match='nested'):
        prepare_raw([{**rows[0], 'n': [1]}], schema)
    with pytest.raises(ValueError, match='nested'):
        prepare_raw([{**rows[0], 'constant': {'bad': 1}}], schema)


def test_preprocessing_nearly_equal_large_bounds_uses_decimal():
    from app.services.normalization import fit_rows
    rows = [{'_id': 'a', 'Label': 'benign', 'value': '100000000000000000000'},
            {'_id': 'b', 'Label': 'attack', 'value': '100000000000000000001'}]
    _, schema = fit_rows(rows)
    prepared, _ = prepare_raw(rows, schema)
    assert prepared[0]['value'] == 0 and prepared[1]['value'] == 1


def test_grouped_classes_split_without_breaking_or_duplicating_blocks():
    blocks = [[{'Label': 'benign', '_id': f'{b}-{i}'} for i in range(10)] for b in range(6)]
    blocks += [[{'Label': 'attack', '_id': f'{b}-{i}'} for i in range(10)] for b in range(6, 10)]
    partitions, indices = split_blocks(blocks)
    assert sorted(index for group in indices for index in group) == list(range(10))
    for part, group in zip(partitions, indices):
        assert {row['Label'] for block in part for row in block} == {'benign', 'attack'}
        assert all(block is blocks[index] for block, index in zip(part, group))
    assert indices == split_blocks(blocks)[1]


@pytest.mark.parametrize('mixed', [0, 1, 2, 3, 4])
def test_minimum_class_coverage_and_adjusted_partition_sizes(mixed):
    blocks = [[{'Label': 'benign'}, {'Label': 'attack'}] for _ in range(mixed)]
    blocks += [[{'Label': label}] for label in ['benign', 'attack'] for _ in range(4 - mixed)]
    while len(blocks) < 5:
        blocks.append([{'Label': 'benign'}, {'Label': 'attack'}])
    partitions, indices = split_blocks(blocks)
    assert sorted(index for group in indices for index in group) == list(range(len(blocks)))
    assert all({row['Label'] for block in part for row in block} == {'benign', 'attack'} for part in partitions)


def test_insufficient_independent_class_blocks_is_actionable():
    blocks = [[{'Label': 'benign'}]] * 8 + [[{'Label': 'attack'}]] * 2
    with pytest.raises(ValueError, match='at least 4 distinct complete blocks') as error:
        split_blocks(blocks)
    assert 'benign=8, attack=2, mixed=0' in str(error.value)


def test_sampling_reaches_late_class_beyond_record_cap(setup):
    client, db, _ = setup
    # All first 80000 rows are benign; attack blocks occur beyond the old prefix cap.
    originals = [{'_id': f'{b:02}-{i:05}', 'Label': 'benign' if b < 8 else 'attack',
                  'signal': '0' if b < 8 else '1'} for b in range(12) for i in range(10000)]
    db.dataset_records.insert_many(originals)
    db.standard_records.insert_many([standard_row(row['_id'], int(row['Label'] == 'attack')) for row in originals])
    diagnostics = {}
    chosen = list(training_blocks(db, 80000, diagnostics))
    assert len(chosen) == 8 and all(len(block) == 10000 for block in chosen)
    assert diagnostics['complete_blocks_scanned'] == 12
    assert diagnostics['block_classes'] == {'benign': 8, 'attack': 4, 'mixed': 0}
    assert diagnostics['selected_block_classes'] == {'benign': 4, 'attack': 4, 'mixed': 0}
    assert max(diagnostics['selected_source_block_indices']) >= 8
    assert len({row['_id'] for block in chosen for row in block}) == 80000
    # Full API training must succeed with the same cap, preserve data, and publish class diagnostics.
    response = client.post('/api/v1/ml/training/runs', json={'max_records': 80000, 'rounds': 10})
    status = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert status['status'] == 'completed', status
    assert status['sampling']['complete_blocks_scanned'] == 12
    metadata = client.get('/api/v1/ml/model').json()
    assert all(counts['benign'] > 0 and counts['attack'] > 0
               for counts in metadata['split']['class_counts'].values())
    # Five pure blocks cannot cover two classes in three independent partitions.
    response = client.post('/api/v1/ml/training/runs', json={'max_records': 50000, 'rounds': 10})
    failed = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert failed['status'] == 'failed' and '80000' in failed['error']
    assert failed['sampling']['block_classes']['attack'] == 4
    assert client.get('/api/v1/ml/model').status_code == 503


def standard_row(key, label, informative=True):
    behavior = {name: 0.0 for name in block_features([{}])[0]}
    behavior['source_record_share'] = float(label) if informative else 0.0
    return {'_id': key, 'original_id': key, 'Label': label, 'constant_original': 0.0,
            'block_index': 0.0, **behavior}


def test_standard_training_uses_stored_behavior_and_never_reads_raw(setup, monkeypatch):
    from pymongo.collection import Collection
    client, db, _ = setup
    db.standard_records.insert_many([standard_row(f'{b}-{i:05}', i % 2)
                                     for b in range(5) for i in range(10000)])
    original_find = Collection.find
    def no_raw(collection, *args, **kwargs):
        if collection.name == 'dataset_records':
            pytest.fail('Training must use standard_records without reconstructing raw features')
        return original_find(collection, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Collection, 'find', no_raw)
        patch.setattr('app.services.machine_learning.fit_rows',
                      lambda *args, **kwargs: pytest.fail('Standard features must not be refitted'))
        patch.setattr('app.services.machine_learning.prepare_raw',
                      lambda *args, **kwargs: pytest.fail('Stored behavior must not be recomputed'))
        response = client.post('/api/v1/ml/training/runs', json={'max_records': 50000, 'rounds': 10})
    result = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert result['status'] == 'completed', result
    assert result['acceptance']['accepted']
    model = client.get('/api/v1/ml/model').json()
    assert model['input_format'] == 'standard'
    assert model['feature_importance_gain']['source_record_share'] > 0
    assert model['feature_importance_gain']['constant_original'] == 0
    assert set(block_features([{}])[0]) <= set(model['features'])
    assert 'block_index' not in model['features']
    for label in (0, 1):
        record = standard_row('new', label)
        record.pop('Label')
        prediction = client.post('/api/v1/ml/predict', json={
            'records': [record]})
        assert prediction.status_code == 200, prediction.text
        assert prediction.json()['items'][0]['predicted_label'] == label
        assert prediction.json()['items'][0]['original_id'] == 'new'
    response = client.post('/api/v1/ml/predict', json={
        'records': [{'n': '1'}], 'input_format': 'raw'})
    assert response.status_code == 422


def test_constant_model_is_rejected_without_retaining_prior_model(setup, trained):
    client, db, _ = setup
    prior, _ = trained
    client.app.state.ml.publish(prior)
    db.standard_records.insert_many([standard_row(f'{b}-{i:05}', i % 2, informative=False)
                                     for b in range(5) for i in range(10000)])
    response = client.post('/api/v1/ml/training/runs', json={'max_records': 50000, 'rounds': 10})
    result = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert result['status'] == 'rejected', result
    assert not result['acceptance']['accepted']
    assert 'All training features are constant' in result['acceptance']['reasons'][0]
    assert client.app.state.ml.active is None
    assert not (client.app.state.ml.directory / 'active.json').exists()
    assert not client.app.state.import_lock.locked()


def test_legacy_degenerate_active_model_is_not_served(setup, trained):
    client, _, _ = setup
    artifact, _ = trained
    bad = {**artifact, 'test_metrics': {'roc_auc': 0.5, 'confusion_matrix': [[0, 11069], [0, 8931]]}}
    client.app.state.ml.publish(bad)
    response = client.post('/api/v1/ml/predict-matrix', json={
        'matrix': [[0] * len(bad['features'])]})
    assert response.status_code == 503
    assert 'retrain' in response.json()['detail']
    metadata = client.get('/api/v1/ml/model').json()
    assert metadata['serving_eligible'] is False
    assert metadata['test_metrics']['roc_auc'] == 0.5


def test_comparison_calibration_and_weight_selection(trained):
    from app.services.machine_learning import choose_weight
    artifact, _ = trained
    assert set(artifact['evaluation']) == {'lightgbm', 'catboost', 'ensemble'}
    for metrics in artifact['evaluation'].values():
        assert metrics['roc_auc'] > 0.95
        assert metrics['false_positive_rate'] < 0.05
        assert sum(map(sum, metrics['confusion_matrix'])) == artifact['split']['test_rows']
    assert artifact['ensemble']['lightgbm_weight'] + artifact['ensemble']['catboost_weight'] == 1
    assert set(artifact['base_calibration']) == {'lightgbm', 'catboost'}
    assert set(artifact['feature_importance_catboost']) == set(artifact['features'])
    groups = artifact['split']['block_indices']
    assert set(groups) == {'train', 'validation', 'calibration', 'test'}
    assert sorted(index for group in groups.values() for index in group) == list(range(5))
    # Weight selection must favor the informative model, not force a 50/50 blend.
    labels = np.asarray([0, 1, 0, 1])
    weight, scores = choose_weight(np.asarray([0.1, 0.9, 0.1, 0.9]), np.asarray([0.9, 0.1, 0.9, 0.1]), labels)
    assert weight == 1 and len(scores) == 11
    assert 'model_version' not in artifact


def test_new_training_replaces_report_and_predictions(setup, trained):
    client, db, _ = setup
    artifact, _ = trained
    client.app.state.ml.publish(artifact)
    db.ml_training_runs.insert_one({'_id': 'old-report', 'status': 'completed'})
    db.ml_predictions.insert_one({'_id': 'old-result', 'predicted_label': 1})
    response = client.post('/api/v1/ml/training/runs', json={'max_records': 50000, 'rounds': 10})
    assert response.json()['id'] == 'current'
    assert list(db.ml_training_runs.distinct('_id')) == ['current']
    assert db.ml_predictions.count_documents({}) == 0
    assert client.app.state.ml.active is None
    assert not (client.app.state.ml.directory / 'active.json').exists()
    assert client.get('/api/v1/ml/model').status_code == 503


def test_reset_during_prediction_does_not_store_old_results(setup, trained, monkeypatch):
    client, db, _ = setup
    artifact, blocks = trained
    manager = client.app.state.ml
    manager.publish(artifact)
    original = Predictor.predict
    def reset_before_return(predictor, *args, **kwargs):
        result = original(predictor, *args, **kwargs)
        manager.clear()
        return result
    monkeypatch.setattr(Predictor, 'predict', reset_before_return)
    response = client.post('/api/v1/ml/predict', json={
        'records': blocks[4][:1], 'input_format': 'raw', 'persist': True})
    assert response.status_code == 503
    assert db.ml_predictions.count_documents({}) == 0
