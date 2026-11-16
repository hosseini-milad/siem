from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def setup():
    config = Settings(mongodb_database='siem_test_' + uuid4().hex)
    mongo = MongoClient(config.mongodb_uri)
    try:
        with TestClient(create_app(config)) as client:
            yield client, mongo[config.mongodb_database]
    finally:
        mongo.drop_database(config.mongodb_database)
        mongo.close()


def run(client):
    response = client.post('/api/v1/normalization/runs')
    assert response.status_code == 202
    return client.get('/api/v1/normalization/runs/' + response.json()['id']).json()


def test_global_scaling_encoding_and_source_preservation(setup):
    client, db = setup
    source = [
        {'_id': 'a', 'Label': 'benign', 'Source File': 'a.csv', 'Src IP': '0.0.0.0', 'Dst IP': '255.255.255.255', 'Protocol': '6', 'Timestamp': '1748677044.142322', 'size': '-10', 'constant': '4', 'CWR Flag Cnt': '', 'service': 'http'},
        {'_id': 'b', 'Label': 'DDoS', 'Src IP': '255.255.255.255', 'Protocol': '17', 'Timestamp': '1748677045.142322', 'size': '10', 'constant': '4', 'service': 'dns'},
        {'_id': 'c', 'Label': 'BENIGN', 'Protocol': '6', 'size': '0', 'constant': '4', 'CWR Flag Cnt': 'NaN', 'service': 'http'},
    ]
    db.dataset_records.insert_many(source)
    status = run(client)
    assert status['status'] == 'completed', status
    rows = list(db.normal_records.find().sort('_id', 1))
    assert [r['size'] for r in rows] == [0, 1, 0.5]
    assert [r['Label'] for r in rows] == [0, 1, 0]
    assert rows[0]['Src IP'] == 0 and rows[1]['Src IP'] == 1
    assert rows[0]['Timestamp'] == 0 and rows[1]['Timestamp'] == 1
    assert rows[0]['Dst IP'] == 1 and rows[1]['Dst IP'] == 0
    assert all(r['constant'] == 0 and r['CWR Flag Cnt'] == 0 for r in rows)
    assert rows[0]['original_id'] == 'a'
    assert 'Source File' not in rows[0] and 'Protocol' not in rows[0]
    for row in rows:
        assert all(isinstance(v, (int, float)) and 0 <= v <= 1 for k, v in row.items() if k not in {'_id', 'original_id'})
    assert list(db.dataset_records.find()) == source
    assert run(client)['status'] == 'completed'
    assert db.normal_records.count_documents({}) == 3
    assert client.get('/api/v1/normalization/records?limit=1').json()['total'] == 3
    assert client.get('/api/v1/normalization/runs/' + str(uuid4())).status_code == 404


def test_failure_preserves_previous_output_and_lock(setup):
    client, db = setup
    db.normal_records.insert_one({'_id': 'old', 'original_id': 'old', 'Label': 0})
    assert run(client)['status'] == 'failed'  # Empty input.
    for row in [{'Label': ''}, {'Label': 'benign', 'Src IP': 'broken'}, {'Label': 'benign', 'n': {'nested': 1}}]:
        db.dataset_records.delete_many({})
        db.dataset_records.insert_one(row)
        assert run(client)['status'] == 'failed'
        assert db.normal_records.find_one()['_id'] == 'old'
    assert not any(name.startswith('normal_staging_') for name in db.list_collection_names())
    client.app.state.import_lock.acquire()
    try:
        assert client.post('/api/v1/normalization/runs').status_code == 409
    finally:
        client.app.state.import_lock.release()


def test_scaling_across_batches_and_atomic_replacement(setup):
    client, db = setup
    db.normal_records.insert_one({'_id': 'stale'})
    db.dataset_records.insert_many([{'_id': str(i), 'Label': 'benign', 'value': str(i)} for i in range(501)])
    assert run(client)['status'] == 'completed'
    assert db.normal_records.count_documents({}) == 501
    assert db.normal_records.find_one({'_id': 'stale'}) is None
    assert db.normal_records.find_one({'_id': '250'})['value'] == 0.5
    assert db.normal_records.find_one({'_id': '500'})['value'] == 1
