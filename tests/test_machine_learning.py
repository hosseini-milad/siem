from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import numpy as np
import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app
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
    assert artifact['split']['train_rows'] == 30000
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
    reloaded = ModelManager(tmp_path, 2).require(artifact['model_version'])
    records, _ = prepare_raw(blocks[4], artifact['normalization_schema'], artifact['behavior_bounds'])
    matrix = feature_matrix(records, artifact['features'])
    expected = reloaded.predict(matrix=matrix)['items']
    assert manager.require().predict(records=blocks[4], raw=True)['items'] == [
        {**row, 'original_id': blocks[4][i]['original_id']} for i, row in enumerate(expected)]
    with ThreadPoolExecutor(2) as executor:
        results = list(executor.map(lambda _: reloaded.predict(matrix=matrix)['items'], range(2)))
    assert results == [expected, expected]
    with pytest.raises(ValueError, match='model_version'):
        manager.require('old')


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
    body = {'model_version': artifact['model_version'], 'records': raw, 'persist': True}
    result = client.post('/api/v1/ml/predict', json=body)
    assert result.status_code == 200, result.text
    assert len(result.json()['items']) == 10000
    assert db.ml_predictions.count_documents({}) == 10000
    assert db.dataset_records.count_documents({}) == 0
    assert db.ml_predictions.find_one({'_id': raw[1]['original_id']})['predicted_label'] == 1
    assert client.post('/api/v1/ml/predict', json=body).status_code == 200
    assert db.ml_predictions.count_documents({}) == 10000
    assert client.post('/api/v1/ml/predict', json={**body, 'model_version': 'old'}).status_code == 409
    assert client.post('/api/v1/ml/predict', json={**body, 'records': []}).status_code == 422
    assert client.post('/api/v1/ml/predict', json={**body, 'records': raw + [raw[0]]}).status_code == 422
    assert client.post('/api/v1/ml/predict', json={**body, 'records': [raw[0], raw[0]]}).status_code == 422
    matrix = np.zeros((10000, len(artifact['features']))).tolist()
    assert client.post('/api/v1/ml/predict-matrix', json={
        'model_version': artifact['model_version'], 'matrix': matrix}).status_code == 200
    assert client.post('/api/v1/ml/predict-matrix', json={
        'model_version': artifact['model_version'], 'matrix': [[0]]}).status_code == 422


def test_database_training_and_restart(setup, trained):
    client, db, config = setup
    _, blocks = trained
    originals = [row for block in blocks for row in block]
    db.dataset_records.insert_many(originals)
    db.standard_records.insert_many([{'_id': row['_id'], 'original_id': row['_id']} for row in originals])
    result = client.post('/api/v1/ml/training/runs', json={'max_records': 50000, 'rounds': 10})
    assert result.status_code == 202
    status = client.get('/api/v1/ml/training/runs/' + result.json()['id']).json()
    assert status['status'] == 'completed', status
    version = status['model_version']
    assert client.get('/api/v1/ml/model').json()['model_version'] == version
    assert db.dataset_records.find_one({'_id': originals[1]['_id']})['Label'] == 'attack'
    db.ml_training_runs.insert_one({'_id': 'interrupted', 'status': 'running'})
    with TestClient(create_app(config)) as restarted:
        assert restarted.get('/api/v1/ml/model').json()['model_version'] == version
        assert db.ml_training_runs.find_one({'_id': 'interrupted'})['status'] == 'interrupted'


def test_training_failure_preserves_active_model_and_unlocks(setup, trained):
    client, db, _ = setup
    artifact, _ = trained
    client.app.state.ml.publish(artifact)
    response = client.post('/api/v1/ml/training/runs', json={})
    status = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert status['status'] == 'failed'
    assert client.app.state.ml.require().version == artifact['model_version']
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
    blocks += [[{'Label': 'attack', '_id': f'{b}-{i}'} for i in range(10)] for b in range(6, 9)]
    partitions, indices = split_blocks(blocks)
    assert sorted(index for group in indices for index in group) == list(range(9))
    for part, group in zip(partitions, indices):
        assert {row['Label'] for block in part for row in block} == {'benign', 'attack'}
        assert all(block is blocks[index] for block, index in zip(part, group))
    assert indices == split_blocks(blocks)[1]


@pytest.mark.parametrize('mixed', [0, 1, 2, 3])
def test_minimum_class_coverage_and_adjusted_partition_sizes(mixed):
    blocks = [[{'Label': 'benign'}, {'Label': 'attack'}] for _ in range(mixed)]
    blocks += [[{'Label': label}] for label in ['benign', 'attack'] for _ in range(3 - mixed)]
    while len(blocks) < 5:
        blocks.append([{'Label': 'benign'}, {'Label': 'attack'}])
    partitions, indices = split_blocks(blocks)
    assert sorted(index for group in indices for index in group) == list(range(len(blocks)))
    assert all({row['Label'] for block in part for row in block} == {'benign', 'attack'} for part in partitions)


def test_insufficient_independent_class_blocks_is_actionable():
    blocks = [[{'Label': 'benign'}]] * 8 + [[{'Label': 'attack'}]] * 2
    with pytest.raises(ValueError, match='at least 3 distinct complete blocks') as error:
        split_blocks(blocks)
    assert 'benign=8, attack=2, mixed=0' in str(error.value)


def test_sampling_reaches_late_class_beyond_record_cap(setup):
    client, db, _ = setup
    # All first 60000 rows are benign; attack blocks occur beyond the old prefix cap.
    originals = [{'_id': f'{b:02}-{i:05}', 'Label': 'benign' if b < 6 else 'attack',
                  'signal': '0' if b < 6 else '1'} for b in range(9) for i in range(10000)]
    db.dataset_records.insert_many(originals)
    db.standard_records.insert_many([{'_id': row['_id'], 'original_id': row['_id'],
                                      'Label': 0 if row['Label'] == 'benign' else 1} for row in originals])
    diagnostics = {}
    chosen = list(training_blocks(db, 60000, diagnostics))
    assert len(chosen) == 6 and all(len(block) == 10000 for block in chosen)
    assert diagnostics['complete_blocks_scanned'] == 9
    assert diagnostics['block_classes'] == {'benign': 6, 'attack': 3, 'mixed': 0}
    assert diagnostics['selected_block_classes'] == {'benign': 3, 'attack': 3, 'mixed': 0}
    assert max(diagnostics['selected_source_block_indices']) >= 6
    assert len({row['_id'] for block in chosen for row in block}) == 60000
    # Full API training must succeed with the same cap, preserve data, and publish class diagnostics.
    response = client.post('/api/v1/ml/training/runs', json={'max_records': 60000, 'rounds': 10})
    status = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert status['status'] == 'completed', status
    assert status['sampling']['complete_blocks_scanned'] == 9
    metadata = client.get('/api/v1/ml/model').json()
    assert all(counts['benign'] > 0 and counts['attack'] > 0
               for counts in metadata['split']['class_counts'].values())
    # Five pure blocks cannot cover two classes in three independent partitions.
    response = client.post('/api/v1/ml/training/runs', json={'max_records': 50000, 'rounds': 10})
    failed = client.get('/api/v1/ml/training/runs/' + response.json()['id']).json()
    assert failed['status'] == 'failed' and '60000' in failed['error']
    assert failed['sampling']['block_classes']['attack'] == 3
    assert client.get('/api/v1/ml/model').json()['model_version'] == metadata['model_version']
