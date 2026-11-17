from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import ExecutionTimeout

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def setup(tmp_path):
    config = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path / 'models'))
    mongo = MongoClient(config.mongodb_uri)
    try:
        with TestClient(create_app(config)) as client:
            yield client, mongo[config.mongodb_database]
    finally:
        mongo.drop_database(config.mongodb_database)
        mongo.close()


def test_swagger_statistics_are_accurate_and_read_only_without_model(setup):
    client, db = setup
    source = [
        {'_id': 'secret-a', 'original_id': 'private-a', 'Label': 0, 'block_index': 0, 'signal': 0, 'partial': 0.5},
        {'_id': 'secret-b', 'original_id': 'private-b', 'Label': 0, 'signal': 1},
        {'_id': 'secret-c', 'original_id': 'private-c', 'Label': 1, 'signal': 2},
        {'_id': 'secret-d', 'original_id': 'private-d', 'Label': 1, 'signal': 'private-value'},
    ]
    db.standard_records.insert_many(source)
    response = client.get('/api/v1/ml/data-diagnostics?full_label_counts=true')
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['read_only'] and result['sampled_records'] == result['total_estimate'] == 4
    assert result['label_distribution_scope'] == 'full_collection'
    assert {row['label']: row['count'] for row in result['label_distribution']} == {0: 2, 1: 2}
    features = {(row['field'], row['label']): row for row in result['features']}
    benign = features['signal', 0]
    assert benign['min'] == 0 and benign['max'] == 1 and benign['stddev'] == 0.5
    assert benign['zeros'] == benign['ones'] == 1 and not benign['constant_in_sample']
    attack = features['signal', 1]
    assert attack['non_numeric'] == 1 and attack['outside_unit_range'] == 1
    assert features['partial', 0]['missing'] == 1
    assert features['partial', 1]['missing'] == 2
    assert features['partial', 1]['samples'] == 0
    assert not {'_id', 'original_id', 'Label', 'block_index'} & {row['field'] for row in result['features']}
    assert 'secret-' not in response.text and 'private-' not in response.text
    assert list(db.standard_records.find()) == source
    assert not db.ml_training_runs.find_one() and not db.ml_predictions.find_one()
    schema = client.get('/openapi.json').json()['paths']['/api/v1/ml/data-diagnostics']['get']
    assert {item['name'] for item in schema['parameters']} == {'sample_size', 'full_label_counts', 'max_time_ms'}


def test_empty_sample_limits_and_nonfinite_values(setup):
    client, db = setup
    response = client.get('/api/v1/ml/data-diagnostics').json()
    assert response['sampled_records'] == 0 and response['features'] == []
    assert response['label_distribution'] == [] and response['label_distribution_scope'] == 'sample'
    db.standard_records.insert_many([
        {'Label': 0, 'bad': float('nan')}, {'Label': 0, 'bad': float('inf')},
        {'Label': 1, 'bad': float('-inf')}, {'Label': 'private-invalid-label', 'bad': {'private': 'value'}},
    ])
    response = client.get('/api/v1/ml/data-diagnostics')
    assert response.status_code == 200, response.text
    assert 'private-invalid-label' not in response.text and '"private"' not in response.text
    rows = response.json()['features']
    assert sum(row['non_finite'] for row in rows) == 3
    assert all(row['min'] is None and row['stddev'] is None for row in rows)
    assert client.get('/api/v1/ml/data-diagnostics?sample_size=2').json()['sampled_records'] == 2
    for params in ['sample_size=0', 'sample_size=50001', 'max_time_ms=999', 'max_time_ms=120001']:
        assert client.get('/api/v1/ml/data-diagnostics?' + params).status_code == 422


def test_timeout_gives_actionable_message(setup, monkeypatch):
    client, db = setup
    def timeout(*args, **kwargs):
        raise ExecutionTimeout('private server details')
    monkeypatch.setattr(Collection, 'aggregate', timeout)
    response = client.get('/api/v1/ml/data-diagnostics')
    assert response.status_code == 504
    assert 'sample_size' in response.json()['detail']
    assert 'private server details' not in response.text
