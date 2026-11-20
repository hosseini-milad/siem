from collections import Counter
from datetime import datetime, timedelta, timezone
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
                      web_access_log_path=str(path), web_local_collector_enabled=False, web_collector_keys={'siem-api': secret, 'remote-api': 'another-test-key'})
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
            assert len(login['auth_subject']) == 64 and 'private-user' not in path.read_text()
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


def test_configurable_web_thresholds_count_distinct_failures_and_link_evidence(tmp_path):
    service = 'test-web'
    key = 'dedicated-collector-key-for-testing'
    config = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path),
                      web_collector_keys={service: key})
    with TestClient(create_app(config)) as client:
        db = client.app.state.database
        try:
            settings_path = '/api/v1/alerts/settings/web'
            rule_settings = client.get(settings_path).json()
            assert rule_settings['login_failure']['threshold'] == 5
            assert rule_settings['server_error']['threshold'] == 10
            rule_settings['server_error']['threshold'] = 2
            assert client.put(settings_path, json=rule_settings).json() == rule_settings

            now = datetime.now(timezone.utc)
            window_end = now.replace(second=0, microsecond=0)
            subject = 'a' * 64

            def request_record(status, number, *, login=False, age=0):
                return {'timestamp': (now - timedelta(minutes=age)).isoformat(),
                        'request_id': f'test-{number}', 'method': 'POST', 'route': '/login',
                        'status': status, 'duration_ms': 1, 'request_bytes': 10, 'response_bytes': 10,
                        'source_ip': f'192.0.2.{number % 200 + 1}',
                        **({'security_event': 'login_failure', 'auth_subject': subject} if login else {})}

            def signed(events):
                codes = Counter(str(row['status']) for row in events)
                classes = Counter(str(row['status'])[0] + 'xx' for row in events)
                batch = {'batch_id': str(uuid4()), 'service': service,
                         'interval_start': (window_end - timedelta(minutes=1)).isoformat(),
                         'interval_end': window_end.isoformat(), 'events': events, 'status_codes': codes,
                         'status_classes': classes, 'latency_buckets': [len(events), *([0] * 10)],
                         'omitted_details': 0, 'invalid_lines': 0}
                payload = json.dumps(batch).encode()
                headers = {'X-SIEM-Service': service,
                           'X-SIEM-Signature': hmac.digest(key.encode(), payload, 'sha256').hex()}
                return payload, headers

            def send(events):
                content, headers = signed(events)
                response = client.post('/api/v1/web-services/batches', content=content, headers=headers)
                assert response.status_code == 202, response.text
                return content, headers

            send([request_record(401, index, login=True) for index in range(4)] + [
                request_record(401, 0, login=True), request_record(429, 5, login=True),
                request_record(401, 6), request_record(401, 7, login=True, age=10),
            ])
            assert db.siem_alerts.count_documents({}) == 0
            content, headers = send([request_record(401, 8, login=True)])
            assert client.post('/api/v1/web-services/batches', content=content, headers=headers).json()['duplicate']
            send([request_record(401, 9, login=True)])
            send([request_record(503, 10), request_record(500, 11)])
            web = client.get('/api/v1/alerts', params={'domain': 'web'}).json()['items']
            assert len(web) == 2
            by_rule = {row['evidence']['rule']: row for row in web}
            login = by_rule['login_failure']
            assert login['evidence']['observed_count'] == 5
            assert login['evidence']['auth_subject'] == subject
            sources = client.get(f"/api/v1/alerts/{login['id']}/evidence").json()['items']
            assert sources and all(row['collection'] == 'web-records' and row['record']['status'] == 401 for row in sources)
            assert by_rule['server_error']['evidence']['observed_count'] == 2
            assert client.get('/api/v1/alerts', params={'domain': 'network'}).json()['total'] == 0
            assert client.get('/api/v1/alerts/summary', params={'domain': 'web'}).json()['total'] == 2
            rule_settings['server_error']['enabled'] = False
            assert client.put(settings_path, json=rule_settings).status_code == 200
            db.web_alert_cooldowns.delete_many({})
            send([request_record(503, 12)])
            assert db.siem_alerts.count_documents({'evidence.rule': 'server_error'}) == 1
        finally:
            db.client.drop_database(config.mongodb_database)


def test_owasp_all_categories_with_isolated_signed_telemetry(tmp_path):
    from app.services.owasp_signals import SIGNALS
    from app.services.web_alerts import check_collectors

    service = 'owasp-test'
    key = 'dedicated-synthetic-collector-key'
    config = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path),
                      web_collector_keys={service: key})
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    minute = now.replace(second=0, microsecond=0)
    path = tmp_path / 'mixed.jsonl'
    common = {'timestamp': now.isoformat(), 'method': 'POST', 'route': '/test',
              'request_bytes': 10, 'response_bytes': 10, 'duration_ms': 1, 'source_ip': '192.0.2.3'}
    rows = [
        {**common, 'request_id': f'{status}-{index}', 'status': status, **markers}
        for status, size, markers in (
            (403, 5, {'security_event': 'access_denied'}),
            (401, 5, {'security_event': 'login_failure', 'auth_subject': 'b' * 64}),
            (503, 10, {}),
        ) for index in range(size)
    ]
    rows.extend({'signal': signal, 'signal_id': f'test-{signal}', 'detector_id': 'synthetic-validation',
                 'timestamp': now.isoformat()} for signal in SIGNALS)
    path.write_text('\n'.join(map(json.dumps, rows)) + '\ninvalid\ninvalid\ninvalid\n')
    with sqlite3.connect(':memory:') as conn:
        conn.executescript('''
            CREATE TABLE cursor (id INTEGER PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER);
            CREATE TABLE pending (id TEXT PRIMARY KEY, interval_end INTEGER, payload BLOB);
        ''')
        aggregate(conn, path, service, minute, 1000)
        batch = json.loads(conn.execute('SELECT payload FROM pending').fetchone()[0])
    assert len(batch['security_signals']) == 6
    batch['events'] = [row for row in batch['events'] if row['status'] != 503]
    batch['omitted_details'] = 10
    payload = json.dumps(batch).encode()
    headers = {'X-SIEM-Service': service, 'X-SIEM-Signature': hmac.digest(key.encode(), payload, 'sha256').hex()}
    with TestClient(create_app(config)) as client:
        db = client.app.state.database
        try:
            endpoint = '/api/v1/web-services/batches'
            response = client.post(endpoint, content=payload, headers=headers)
            assert response.status_code == 202, response.text
            assert client.post(endpoint, content=payload, headers=headers).json()['duplicate']
            rows = client.get('/api/v1/alerts', params={'domain': 'web'}).json()['items']
            assert len(rows) == 10
            by_category = {row['owasp_category']: row for row in rows}
            assert set(by_category) == {f'A{n:02}' for n in range(1, 11)}
            evaluation = client.post('/api/v1/alerts/owasp/evaluate', params={'service': service})
            assert evaluation.status_code == 200, evaluation.text
            assert evaluation.json()['alerts_created'] == 0
            assert client.post('/api/v1/alerts/owasp/evaluate', params={'service': 'unknown'}).status_code == 404
            assert by_category['A10']['evidence']['observed_count'] == 10
            assert by_category['A10']['evidence']['web_record_ids'] == []
            for category, expected in (('A01', 'web-records'), ('A05', 'web_security_signals'),
                                       ('A09', 'web_service_batches'), ('A10', 'web_service_batches')):
                alert_id = by_category[category]['id']
                result = client.get(f'/api/v1/alerts/{alert_id}/evidence').json()['items']
                assert any(item['collection'] == expected and item['record'] for item in result)
            check_collectors(db, (service,), now + timedelta(minutes=6))
            missing = db.siem_alerts.find_one({'owasp_category': 'A09', 'evidence.signal': 'missing_heartbeat'})
            assert missing and missing['evidence']['silent_seconds'] >= 300
        finally:
            db.client.drop_database(config.mongodb_database)
