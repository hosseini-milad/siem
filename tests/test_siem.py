from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app
from app.services import siem
from app.services.elk import Elk


@pytest.fixture
def setup(tmp_path):
    config = Settings(mongodb_database='siem_test_' + uuid4().hex, ml_model_dir=str(tmp_path / 'model'))
    mongo = MongoClient(config.mongodb_uri)
    try:
        with TestClient(create_app(config)) as client:
            yield client, mongo[config.mongodb_database]
    finally:
        mongo.drop_database(config.mongodb_database)
        mongo.close()


def event(**changes):
    return {'timestamp': datetime.now(timezone.utc).isoformat(), 'source': 'firewall',
            'level': 'WARNING', 'message': 'Connection denied', 'attributes': {'source_ip': '192.0.2.1'}, **changes}


def test_menu_tags_and_no_authentication(setup):
    client, db = setup
    spec = client.get('/openapi.json').json()
    declared = {item['name'] for item in spec['tags']}
    used = {tag for path in spec['paths'].values() for operation in path.values()
            if isinstance(operation, dict) for tag in operation.get('tags', [])}
    assert used <= declared
    assert {'Elasticsearch', 'Logstash', 'Kibana', 'Alerts', 'Incidents', 'Detection Rules'} <= declared
    assert not spec.get('security') and not spec.get('components', {}).get('securitySchemes')
    menu = client.get('/api/v1/system/navigation').json()
    assert not menu['authentication'] and not menu['agents_in_scope']
    assert all(set(item['tags']) <= declared for item in menu['menus'])
    assert client.get('/api/v1/system/status').json()['mongodb']['available']


def test_alert_incident_lifecycle_and_evidence_validation(setup):
    client, db = setup
    record = client.post('/api/v1/logs', json=event()).json()
    body = {'title': 'Review traffic', 'description': 'Unexpected activity', 'severity': 'high', 'event_ids': [record['id']]}
    response = client.post('/api/v1/alerts', json=body)
    assert response.status_code == 201, response.text
    alert = response.json()
    assert client.patch('/api/v1/alerts/' + alert['id'], json={'status': 'acknowledged'}).json()['status'] == 'acknowledged'
    assert client.get('/api/v1/alerts?status=acknowledged&severity=high').json()['total'] == 1
    response = client.post('/api/v1/incidents', json={'title': 'Investigate', 'description': 'Review alert', 'alert_ids': [alert['id']]})
    assert response.status_code == 201, response.text
    incident = response.json()
    assert client.post('/api/v1/incidents/' + incident['id'] + '/notes', json={'text': 'Checked firewall'}).json()['notes'][0]['text'] == 'Checked firewall'
    assert client.patch('/api/v1/incidents/' + incident['id'], json={'status': 'closed'}).json()['status'] == 'closed'
    assert client.get('/api/v1/incidents?status=closed').json()['total'] == 1
    assert client.get('/api/v1/overview').json()['active_incidents'] == 0
    assert client.post('/api/v1/alerts', json={**body, 'event_ids': [str(uuid4())]}).status_code == 422
    assert client.post('/api/v1/alerts', json={**body, 'event_ids': [record['id']] * 2}).status_code == 422
    assert client.patch('/api/v1/alerts/' + alert['id'], json={'status': 'invalid'}).status_code == 422
    assert client.get('/api/v1/incidents/' + str(uuid4())).status_code == 404


def test_threshold_rules_and_ml_alerts_are_deduplicated(setup, monkeypatch):
    client, db = setup
    stamp = datetime.now(timezone.utc)
    monkeypatch.setattr(siem, 'now', lambda: stamp)
    for _ in range(3):
        assert client.post('/api/v1/logs', json=event(timestamp=stamp.isoformat())).status_code == 201
    body = {'name': 'Burst', 'description': 'Three warnings', 'threshold': 3, 'source': 'firewall', 'level': 'WARNING'}
    response = client.post('/api/v1/detections/rules', json=body)
    assert response.status_code == 201
    rule = response.json()
    assert client.post('/api/v1/detections/evaluate').json()['alerts_created'] == 1
    assert client.post('/api/v1/detections/evaluate').json()['alerts_created'] == 0
    assert client.patch('/api/v1/detections/rules/' + rule['id'], json={'enabled': False}).status_code == 200
    assert client.post('/api/v1/detections/evaluate').json()['evaluated_rules'] == 0
    db.ml_predictions.insert_many([{'_id': 'raw-a', 'attack_probability': 0.99}, {'_id': 'raw-b', 'attack_probability': 0.1}])
    assert client.post('/api/v1/alerts/from-predictions', json={}).json()['alerts_created'] == 1
    assert client.post('/api/v1/alerts/from-predictions', json={}).json()['deduplicated'] == 1
    assert db.siem_alerts.count_documents({}) == 2
    assert db.ml_predictions.count_documents({}) == 2
    assert client.get('/api/v1/overview').json()['event_count'] == 3


def test_logstash_receiver_is_idempotent_and_rejects_conflicting_payload(setup):
    client, db = setup
    body = {'batch_id': str(uuid4()), 'events': [event(), event(source='router')]}
    first = client.post('/api/v1/ingestion/logstash', json=body)
    assert first.status_code == 200, first.text
    assert first.json()['inserted'] == 2
    assert client.post('/api/v1/ingestion/logstash', json=body).json()['deduplicated'] == 2
    assert client.get('/api/v1/ingestion/batches/' + body['batch_id']).json()['status'] == 'stored'
    changed = {**body, 'events': [event(message='changed')]}
    assert client.post('/api/v1/ingestion/logstash', json=changed).status_code == 409
    assert db.log_events.count_documents({}) == 2


def test_elasticsearch_checkpoint_retries_and_late_events(setup):
    client, db = setup
    client.post('/api/v1/logs', json=event())
    calls = []
    fail = [True]
    def upstream(request):
        calls.append(request)
        if request.url.path.startswith('/_cat/indices'):
            return httpx.Response(200, json=[{'index': 'siem-events'}])
        if request.url.path.endswith('/_mapping'):
            return httpx.Response(200, json={'siem-events': {'mappings': {'properties': {'@timestamp': {'type': 'date'}}}}})
        if request.url.path == '/_bulk':
            return httpx.Response(200, json={'errors': fail[0], 'items': [{'index': {'status': 201}}]})
        raise AssertionError(str(request.url))
    with httpx.Client(transport=httpx.MockTransport(upstream)) as transport:
        client.app.state.elk = Elk(client.app.state.settings, transport)
        assert client.post('/api/v1/elasticsearch/sync', json={'limit': 500}).status_code == 503
        assert db.elastic_sync_state.find_one() is None
        assert '_search_index' not in db.log_events.find_one()
        fail[0] = False
        assert client.post('/api/v1/elasticsearch/sync', json={'limit': 500}).json()['indexed'] == 1
        assert client.post('/api/v1/elasticsearch/sync', json={'limit': 500}).json()['indexed'] == 0
        # A later insert with an older receipt time must still be discovered.
        row = db.log_events.find_one()
        db.log_events.insert_one({**row, '_id': str(uuid4()), 'received_at': datetime(2020, 1, 1, tzinfo=timezone.utc), '_search_index': None})
        assert client.post('/api/v1/elasticsearch/sync', json={'limit': 500}).json()['indexed'] == 1
    response = client.get('/api/v1/logs').json()
    assert response['total'] == 2 and '_search_index' not in str(response)


def test_upstream_unavailable_is_reported_without_fake_success(setup):
    client, db = setup
    def offline(request):
        raise httpx.ConnectError('private connection details', request=request)
    with httpx.Client(transport=httpx.MockTransport(offline)) as transport:
        client.app.state.elk = Elk(client.app.state.settings, transport)
        assert client.get('/api/v1/elasticsearch/status').json()['available'] is False
        assert client.post('/api/v1/kibana/setup').status_code == 503
        assert client.get('/api/v1/search/events').status_code == 503
        assert 'private connection details' not in client.get('/api/v1/kibana/status').text
