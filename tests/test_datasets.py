import gzip
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def setup(tmp_path):
    folder = tmp_path / 'Benign'
    folder.mkdir()
    config = Settings(datasets_root=str(tmp_path), mongodb_database='siem_test_' + uuid4().hex)
    mongo = MongoClient(config.mongodb_uri)
    try:
        with TestClient(create_app(config)) as client:
            yield client, folder, mongo[config.mongodb_database]
    finally:
        mongo.drop_database(config.mongodb_database)
        mongo.close()


def test_split_gzip_import_and_repeat(setup):
    client, folder, db = setup
    payload = gzip.compress('time,message\n1,"hello, world"\n2,سلام\n'.encode())
    for n, chunk in enumerate([payload[:13], payload[13:27], payload[27:]], 1):
        (folder / f'Benign.csv.gz.{n:03}').write_bytes(chunk)
    assert client.get('/api/v1/datasets/folders').json()['folders'] == ['Benign']
    for expected in [2, 0]:
        response = client.post('/api/v1/datasets/imports', json={'folder': 'Benign'})
        assert response.status_code == 202
        status = client.get('/api/v1/datasets/imports/' + response.json()['id']).json()
        assert status['status'] == 'completed', status
        assert status['inserted'] == expected
        assert status['processed'] == 2
    rows = client.get('/api/v1/datasets/records?folder=Benign').json()
    assert rows['total'] == 2
    assert any(row['data']['message'] == 'سلام' for row in rows['items'])
    assert db.dataset_records.count_documents({}) == 2


def test_invalid_paths_parts_and_csv(setup):
    client, folder, db = setup
    for name in ['..', '../Benign', '/etc', 'missing', 'Benign']:
        assert client.post('/api/v1/datasets/imports', json={'folder': name}).status_code == 422
    (folder / 'data.csv.gz.002').write_bytes(b'bad')
    assert client.post('/api/v1/datasets/imports', json={'folder': 'Benign'}).status_code == 422
    (folder / 'data.csv.gz.002').unlink()
    (folder / 'data.csv').write_text('a,a\n1,2\n')
    job = client.post('/api/v1/datasets/imports', json={'folder': 'Benign'}).json()['id']
    assert client.get('/api/v1/datasets/imports/' + job).json()['status'] == 'failed'
    assert db.dataset_records.count_documents({}) == 0


def test_gzip_crc_failure_and_partial_batches(setup):
    client, folder, db = setup
    payload = bytearray(gzip.compress(('a\n' + 'value\n' * 501).encode()))
    payload[-8] ^= 1
    (folder / 'bad.csv.gz').write_bytes(payload)
    job = client.post('/api/v1/datasets/imports', json={'folder': 'Benign'}).json()['id']
    status = client.get('/api/v1/datasets/imports/' + job).json()
    assert status['status'] == 'failed'
    assert status['processed'] == db.dataset_records.count_documents({})


def test_missing_root_and_busy(setup):
    client, folder, db = setup
    (folder / 'data.csv').write_text('a\nvalue\n')
    client.app.state.import_lock.acquire()
    try:
        assert client.post('/api/v1/datasets/imports', json={'folder': 'Benign'}).status_code == 409
    finally:
        client.app.state.import_lock.release()
    client.app.state.settings.datasets_root = str(folder / 'absent')
    assert client.get('/api/v1/datasets/folders').status_code == 503
