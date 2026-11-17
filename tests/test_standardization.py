from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app
from app.services.standardization import block_features


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
    response = client.post('/api/v1/standardization/runs')
    assert response.status_code == 202
    return client.get('/api/v1/standardization/runs/' + response.json()['id']).json()


def test_context_statistics_and_missing_values():
    rows = [
        {'Src IP': 'a', 'Dst IP': 'x', 'Dst Port': '80', 'Timestamp': '10',
         'TotLen Fwd Pkts': '100', 'TotLen Bwd Pkts': '20', 'Tot Fwd Pkts': '2', 'Tot Bwd Pkts': '1'},
        {'Src IP': 'a', 'Dst IP': 'y', 'Dst Port': '443', 'Timestamp': '2'},
        {'Src IP': 'a', 'Dst IP': 'x', 'Dst Port': '80', 'Timestamp': '4'},
        {'Src IP': 'b', 'Dst IP': 'x', 'Timestamp': '5'},
        {'Src IP': '', 'Timestamp': 'NaN'},
    ]
    first, _, _, fourth, missing = block_features(rows)
    assert first['source_record_count'] == 3
    assert first['source_record_share'] == 3 / 5
    assert first['destination_record_count'] == 3
    assert first['source_destination_record_count'] == 2
    assert first['source_unique_destination_count'] == 2
    assert first['source_unique_destination_port_count'] == 2
    assert first['destination_unique_source_count'] == 2
    assert first['source_interarrival_mean_seconds'] == 4
    assert first['source_interarrival_std_seconds'] == 2
    assert first['block_duration_seconds'] == 8
    assert first['source_total_bytes'] == 120 and first['source_byte_samples'] == 1
    assert first['source_total_packets'] == 3 and first['source_packet_samples'] == 1
    assert fourth['source_interarrival_mean_seconds'] == 0
    assert missing['source_record_count'] == 0 and missing['timestamp_available'] == 0
    assert missing['source_unique_destination_count'] == 0


def test_real_10000_boundary_preservation_and_rebuild(setup):
    client, db = setup
    source = [{'_id': f'{i:05}', 'Src IP': 'a', 'Dst IP': 'x', 'Timestamp': str(i),
               'Dst Port': str(i % 2)} for i in range(10001)]
    normalized = [{'_id': row['_id'], 'original_id': row['_id'], 'Label': i % 2,
                   'value': i / 10000, 'Protocol__category_0': 1} for i, row in enumerate(source)]
    db.dataset_records.insert_many(source)
    db.normal_records.insert_many(normalized)
    result = run(client)
    assert result['status'] == 'completed', result
    assert result['processed'] == 10001 and result['blocks'] == 2
    first = db.standard_records.find_one({'_id': '00000'})
    tail = db.standard_records.find_one({'_id': '10000'})
    assert first.pop('behavior_features')['source_record_count'] == 10000
    assert first == normalized[0]
    assert tail['behavior_features']['block_index'] == 1
    assert tail['behavior_features']['source_record_count'] == 1
    assert tail['behavior_features']['block_duration_seconds'] == 0
    assert list(db.normal_records.find().sort('_id', 1)) == normalized
    assert list(db.dataset_records.find().sort('_id', 1)) == source
    # Fill the previous partial block: existing context must be recalculated.
    db.dataset_records.insert_one({'_id': '10001', 'Src IP': 'a', 'Dst IP': 'y', 'Timestamp': '10002'})
    db.normal_records.insert_one({'_id': '10001', 'original_id': '10001', 'Label': 0})
    assert run(client)['status'] == 'completed'
    tail = db.standard_records.find_one({'_id': '10000'})
    assert tail['behavior_features']['source_record_count'] == 2
    assert tail['behavior_features']['source_unique_destination_count'] == 2
    assert db.standard_records.count_documents({}) == 10002
    assert run(client)['processed'] == 10002
    assert db.standard_records.find_one({'_id': '10000'}) == tail
    response = client.get('/api/v1/standardization/records?limit=1').json()
    assert response['total'] == 10002 and len(response['items']) == 1


def test_original_id_is_join_key_not_output_id(setup):
    client, db = setup
    db.dataset_records.insert_one({'_id': 'raw', 'Src IP': 'a'})
    db.normal_records.insert_one({'_id': 'normalized', 'original_id': 'raw', 'Label': 0})
    assert run(client)['status'] == 'completed'
    row = db.standard_records.find_one()
    assert row['_id'] == 'normalized' and row['original_id'] == 'raw'
    assert row['behavior_features']['source_record_count'] == 1


def test_missing_original_collision_failure_and_lock_release(setup):
    client, db = setup
    db.normal_records.insert_one({'_id': 'a', 'original_id': 'a'})
    result = run(client)
    assert result['status'] == 'failed' and 'missing' in result['error']
    assert db.standard_records.count_documents({}) == 0
    db.dataset_records.insert_one({'_id': 'a'})
    db.normal_records.update_one({'_id': 'a'}, {'$set': {'behavior_features': 'preserve me'}})
    result = run(client)
    assert result['status'] == 'failed' and 'reserved' in result['error']
    db.normal_records.update_one({'_id': 'a'}, {'$unset': {'behavior_features': ''}})
    assert run(client)['status'] == 'completed'
    client.app.state.import_lock.acquire()
    try:
        assert client.post('/api/v1/standardization/runs').status_code == 409
        assert client.post('/api/v1/normalization/runs').status_code == 409
    finally:
        client.app.state.import_lock.release()
    assert client.get('/api/v1/standardization/runs/' + str(uuid4())).status_code == 404


def test_empty_and_startup_interruption(setup):
    client, db = setup
    assert run(client)['processed'] == 0
    db.standardization_runs.insert_one({'_id': 'old', 'status': 'running'})
    with TestClient(create_app(Settings(mongodb_database=db.name))):
        assert db.standardization_runs.find_one({'_id': 'old'})['status'] == 'interrupted'
