from datetime import datetime, timezone
import hmac
import json
import sqlite3
from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from scripts.collect_web_logs import BOUNDS, aggregate


def test_web_access_collection_and_signed_replay(tmp_path):
    path = tmp_path / 'access.jsonl'
    secret = 'test-collector-secret-only-for-tests'
    config = Settings(mongodb_database='siem_test_' + uuid4().hex,
                      ml_model_dir=str(tmp_path / 'model'),
                      web_access_log_path=str(path), web_collector_keys={'siem-api': secret, 'remote-api': 'another-test-key'})
    app = create_app(config)
    with TestClient(app) as client:
        db = app.state.database
        try:
            status_url = '/api/v1/web-services/status'
            status = client.get(status_url).json()
            assert status['local_logging_enabled'] and status['interval_seconds'] == 60
            assert status['items'] == [
                {'service': 'remote-api', 'state': 'awaiting_first_batch'},
                {'service': 'siem-api', 'state': 'awaiting_first_batch'},
            ]
            assert secret not in str(status)
            response = client.get('/api/v1/health?hidden=private-value',
                                  headers={'Authorization': 'Bearer private-value'})
            assert response.status_code == 200
            generated = json.loads(path.read_text().splitlines()[-1])
            assert generated['route'] == '/api/v1/health'
            assert generated['request_id'] == response.headers['x-request-id']
            assert 'private-value' not in path.read_text()

            denied = client.post('/api/v1/auth/login', json={'username': 'private-user', 'password': 'private-password'})
            assert denied.status_code == 401
            login = json.loads(path.read_text().splitlines()[-1])
            assert login['security_event'] == 'login_failure'
            assert login['request_headers']['content_type'] == 'application/json'
            assert login['response_body_fields'] == ['detail']
            assert 'private-password' not in path.read_text()

            with path.open('a') as log:
                log.write(json.dumps({**generated, 'status': 503, 'duration_ms': 75,
                                      'response_body': 'must-not-appear', 'request_body_fields': ['id', 'password'],
                                      'response_headers': {'content_type': 'application/json', 'set-cookie': 'private-cookie'}}) + '\n')
            conn = sqlite3.connect(tmp_path / 'queue.sqlite')
            conn.executescript('''
                CREATE TABLE cursor (id INTEGER PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER);
                CREATE TABLE pending (id TEXT PRIMARY KEY, interval_end INTEGER, payload BLOB);
            ''')
            end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            aggregate(conn, path, 'siem-api', end, 1000)
            aggregate(conn, path, 'siem-api', end, 1000)
            (payload,), = conn.execute('SELECT payload FROM pending').fetchall()
            conn.execute('DELETE FROM pending')
            aggregate(conn, path, 'siem-api', end, 1000, heartbeat=True)
            (heartbeat,), = conn.execute('SELECT payload FROM pending').fetchall()
            conn.close()

            url = '/api/v1/web-services/batches'
            headers = {'X-SIEM-Service': 'siem-api',
                       'X-SIEM-Signature': hmac.digest(secret.encode(), payload, 'sha256').hex()}
            before = path.read_bytes()
            assert client.post(url, content=payload, headers={'X-SIEM-Service': 'siem-api'}).status_code == 401
            first = client.post(url, content=payload, headers=headers)
            assert first.status_code == 202, first.text
            assert not first.json()['duplicate']
            assert client.post(url, content=payload, headers=headers).json()['duplicate']
            assert path.read_bytes() == before
            conflict = payload + b' '
            headers['X-SIEM-Signature'] = hmac.digest(secret.encode(), conflict, 'sha256').hex()
            assert client.post(url, content=conflict, headers=headers).status_code == 409
            stored = client.get(url, params={'service': 'siem-api'}).json()
            assert stored['histogram_upper_bounds_ms'] == list(BOUNDS)
            batch, = stored['items']
            assert batch['status_codes'] == {'200': 2, '401': 1, '503': 1}
            assert sum(batch['latency_buckets']) == 4 and batch['latency_buckets'][4] >= 1
            assert batch['omitted_details'] == 2
            detail = next(row for row in batch['events'] if row['status'] == 503)
            assert 'response_body' not in detail and detail['request_body_fields'] == ['id']
            assert detail['response_headers'] == {'content_type': 'application/json'}
            records = db['web-records']
            assert records.count_documents({}) == 2
            assert records.index_information()['received_at_1']['expireAfterSeconds'] == 7 * 86400
            query = '/api/v1/explorer/web-records'
            page = client.get(query, params={'service': 'siem-api', 'method': 'GET', 'status': 503,
                                            'min_duration_ms': 70, 'route': '/api/v1/hea'}).json()
            assert page['total'] == 1 and page['items'][0]['request_id'] == detail['request_id']
            assert client.get(query, params={'route': '/api/.*'}).json()['total'] == 0
            records.delete_one({'status': 503})
            headers['X-SIEM-Signature'] = hmac.digest(secret.encode(), payload, 'sha256').hex()
            assert client.post(url, content=payload, headers=headers).json()['duplicate']
            assert records.count_documents({}) == 2
            status = client.get(status_url).json()['items'][1]
            assert status['state'] == 'receiving'
            assert status['requests'] == 4 and status['details'] == 2
            headers['X-SIEM-Signature'] = hmac.digest(secret.encode(), heartbeat, 'sha256').hex()
            assert client.post(url, content=heartbeat, headers=headers).status_code == 202
            assert json.loads(heartbeat)['status_codes'] == {}
            assert records.count_documents({}) == 2
        finally:
            db.client.drop_database(config.mongodb_database)
