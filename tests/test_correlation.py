from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def test_unsupervised_correlation_ranks_burst_and_abstains_without_identity_or_history(tmp_path):
    config = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path))
    with TestClient(create_app(config)) as client:
        db = client.app.state.database
        try:
            end = datetime.now(timezone.utc).replace(microsecond=0)
            ip = '192.0.2.10'
            system_ip = 'aa:bb:cc:dd:ee:01'
            for hour in range(1, 13):
                timestamp = end - timedelta(hours=hour, minutes=10)
                db.log_events.insert_one({'_id': f'network-{hour}', 'timestamp': timestamp,
                                          'attributes': {'source_ip': ip, 'destination_ip': '198.51.100.11'}})
                db.agent_logs.insert_one({'_id': f'agent-{hour}', 'timestamp': timestamp, 'device_ip': ip,
                                          'source_ip': '198.51.100.15', 'mac': system_ip})
                db['web-records'].insert_one({'_id': f'web-{hour}', 'timestamp': timestamp,
                                               'source_ip': ip, 'status': 404, 'service': 'api'})
            current = end - timedelta(minutes=10)
            db.log_events.insert_one({'_id': 'network-now', 'timestamp': current,
                                      'attributes': {'source_ip': ip, 'destination_ip': '198.51.100.11'}})
            db.log_events.insert_one({'_id': 'mirrored', 'timestamp': current,
                                      'attributes': {'source_ip': ip, 'agent_id': 'host-1'}})
            db.agent_logs.insert_one({'_id': 'agent-now', 'timestamp': current, 'device_ip': ip,
                                      'source_ip': '198.51.100.15', 'mac': system_ip})
            db['web-records'].insert_one({'_id': 'web-now', 'timestamp': current,
                                           'source_ip': ip, 'status': 404, 'service': 'api'})
            params = {'ip': ip, 'end': end.isoformat(), 'baseline_hours': 16}
            path = '/api/v1/explorer/correlation'
            stable = client.get(path, params=params)
            assert stable.status_code == 200, stable.text
            assert stable.json()['state'] == 'within_baseline'
            assert stable.json()['score'] == 0
            assert stable.json()['features']['network_events'] == 1

            db['web-records'].insert_many([
                {'_id': f'web-burst-{index}', 'timestamp': current, 'source_ip': ip,
                 'status': 503, 'service': 'api', 'route': '/test'} for index in range(15)
            ])
            result = client.get(path, params=params).json()
            assert result['state'] == 'anomalous'
            assert result['active_baseline_windows'] == 12
            assert result['score'] > 10
            assert result['reasons'][0]['feature'] == 'web_events'
            assert {row['collection'] for row in result['graph']['evidence']} == {
                'log_events', 'agent_logs', 'web-records',
            }
            assert result['graph']['evidence_total'] == 18
            assert result['graph']['evidence_shown'] == 14

            db.agent_logs.insert_one({'_id': 'another-host', 'timestamp': current,
                                      'device_ip': ip, 'mac': 'aa:bb:cc:dd:ee:02'})
            ambiguous = client.get(path, params=params).json()
            assert ambiguous['state'] == 'ambiguous_identity' and ambiguous['score'] is None

            sparse_ip = '192.0.2.99'
            db['web-records'].insert_one({'_id': 'sparse', 'timestamp': current, 'source_ip': sparse_ip})
            sparse = client.get(path, params={**params, 'ip': sparse_ip}).json()
            assert sparse['state'] == 'insufficient_baseline' and sparse['score'] is None
        finally:
            db.client.drop_database(config.mongodb_database)
