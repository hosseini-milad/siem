from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app
from app.services.standardization import block_features, scale_features


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
    assert 'behavior_features' not in first
    assert first['source_record_count'] == 1
    assert {key: first[key] for key in normalized[0]} == normalized[0]
    assert tail['block_index'] == 1
    assert tail['source_record_count'] == 0
    assert tail['block_duration_seconds'] == 0
    parameters = db.standardization_parameters.find_one({'_id': 'default'})
    for row in db.standard_records.find():
        assert all(isinstance(v, (int, float)) and 0 <= v <= 1
                   for k, v in row.items() if k not in {'_id', 'original_id'})
    assert list(db.normal_records.find().sort('_id', 1)) == normalized
    assert list(db.dataset_records.find().sort('_id', 1)) == source
    # Fill the previous partial block: existing context must be recalculated.
    db.dataset_records.insert_one({'_id': '10001', 'Src IP': 'a', 'Dst IP': 'y', 'Timestamp': '10002'})
    db.normal_records.insert_one({'_id': '10001', 'original_id': '10001', 'Label': 0})
    assert run(client)['status'] == 'completed'
    tail = db.standard_records.find_one({'_id': '10000'})
    assert tail['source_record_count'] == pytest.approx(1 / 9999)
    assert tail['source_unique_destination_count'] == 0  # Initially constant feature stays zero.
    assert db.standardization_parameters.find_one({'_id': 'default'}) == parameters
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
    assert row['source_record_count'] == 0  # Constant Min-Max feature.
    assert row['source_ip_available'] == 1


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
    assert db.standardization_parameters.find_one() is None
    db.standardization_runs.insert_one({'_id': 'old', 'status': 'running'})
    with TestClient(create_app(Settings(mongodb_database=db.name))):
        assert db.standardization_runs.find_one({'_id': 'old'})['status'] == 'interrupted'


def test_scaling_range_clipping_and_flags():
    bounds = {'source_total_bytes': {'min': 10, 'max': 30},
              'source_record_share': {'min': 0.2, 'max': 0.8},
              'timestamp_available': {'min': 1, 'max': 1},
              'block_size': {'min': 10000, 'max': 10000}}
    feature = {'source_total_bytes': 20, 'source_record_share': 0.25,
               'timestamp_available': 1, 'block_size': 10000}
    assert scale_features(feature, bounds) == {'source_total_bytes': 0.5,
        'source_record_share': 0.25, 'timestamp_available': 1, 'block_size': 0}
    for value, expected in [(-10, 0), (40, 1)]:
        assert scale_features({**feature, 'source_total_bytes': value}, bounds)['source_total_bytes'] == expected
    with pytest.raises(ValueError, match='Nonfinite'):
        scale_features({**feature, 'source_total_bytes': float('inf')}, bounds)


def test_flat_collision_and_legacy_output_migration(setup):
    client, db = setup
    db.dataset_records.insert_many([
        {'_id': 'a', 'Src IP': 'same'}, {'_id': 'b', 'Src IP': 'same'},
        {'_id': 'c', 'Src IP': 'other'},
    ])
    db.normal_records.insert_many([{'_id': key, 'original_id': key, 'Label': 0}
                                   for key in ['a', 'b', 'c']])
    db.standard_records.insert_one({'_id': 'a', 'original_id': 'a', 'behavior_features': {'old': 123}})
    assert run(client)['status'] == 'completed'
    a = db.standard_records.find_one({'_id': 'a'})
    c = db.standard_records.find_one({'_id': 'c'})
    assert 'behavior_features' not in a
    assert a['source_record_count'] == 1 and c['source_record_count'] == 0
    assert a['source_record_share'] == 2 / 3
    db.normal_records.update_one({'_id': 'a'}, {'$set': {'source_record_count': 0.5}})
    assert run(client)['status'] == 'failed'
    assert db.standard_records.find_one({'_id': 'a'}) == a
    assert db.normal_records.find_one({'_id': 'a'})['source_record_count'] == 0.5



def test_finalize_new_dataset_records_and_expose_standard_label(setup):
    client, db = setup
    db.dataset_records.insert_one({'_id': 'clean', 'Label': 'Benign', 'Timestamp': '1747584000'})
    first = client.post('/api/v1/standardization/finalize')
    assert first.status_code == 202
    first_run = first.json()
    assert client.get('/api/v1/standardization/runs/' + first_run['id']).json()['status'] == 'completed'
    assert db.standard_records.find_one({'original_id': 'clean'})['Label'] == 0

    db.dataset_records.insert_one({'_id': 'second', 'Label': 'DDoS', 'Timestamp': '1747584001'})
    resp = client.post('/api/v1/standardization/finalize')
    assert resp.status_code == 202
    job = resp.json()
    assert client.get('/api/v1/standardization/runs/' + job['id']).json()['status'] == 'completed'
    normalization = client.get('/api/v1/normalization/runs/' + job['normalization_run_id']).json()
    assert normalization['processed'] == 1 and normalization['skipped'] == 1
    assert db.standard_records.count_documents({}) == 2
    result = client.get('/api/v1/explorer/records', params={'risk': 'attack'}).json()
    assert result['total'] == 1
    row = result['items'][0]
    assert row['raw']['Label'] == 'DDoS'
    assert row['standardized']['original_id'] == 'second'
    assert row['risk'] == {'score': 1, 'severity': 'attack'}
