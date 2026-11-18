from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

from app.core.config import Settings
from app.main import create_app
from app.services import siem


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


def test_operational_menu_tags(setup):
    client, db = setup
    spec = client.get('/openapi.json').json()
    declared = {item['name'] for item in spec['tags']}
    used = {tag for path in spec['paths'].values() for operation in path.values()
            if isinstance(operation, dict) for tag in operation.get('tags', [])}
    assert used <= declared
    assert {'Overview', 'Search', 'Ingestion', 'Alerts', 'Incidents', 'Detection Rules'} <= declared
    assert {'Elasticsearch', 'Logstash', 'Kibana'}.isdisjoint(declared)
    assert '/api/v1/ingestion/logstash' not in spec['paths']
    assert not spec.get('security') and not spec.get('components', {}).get('securitySchemes')
    menu = client.get('/api/v1/system/navigation').json()
    assert not menu['authentication'] and not menu['agents_in_scope']
    assert [tag for item in menu['menus'] for tag in item['tags']] == [item['name'] for item in spec['tags'] if item['name'] != 'Access']
    assert client.get(menu['dashboard_path']).status_code == 200
    settings = client.get('/api/v1/system/settings').json()
    assert settings['mongodb_database'] == db.name
    assert 'mongodb_uri' not in settings
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


def test_batch_receiver_is_idempotent_and_rejects_conflicting_payload(setup):
    client, db = setup
    body = {'batch_id': str(uuid4()), 'events': [event(), event(source='router')]}
    first = client.post('/api/v1/ingestion/batches', json=body)
    assert first.status_code == 200, first.text
    assert first.json()['inserted'] == 2
    assert client.post('/api/v1/ingestion/logstash', json=body).json()['deduplicated'] == 2
    assert client.get('/api/v1/ingestion/batches/' + body['batch_id']).json()['status'] == 'stored'
    changed = {**body, 'events': [event(message='changed')]}
    assert client.post('/api/v1/ingestion/batches', json=changed).status_code == 409
    assert db.log_events.count_documents({}) == 2


def test_native_search_and_charts_include_legacy_and_new_events(setup):
    client, db = setup
    existing = client.post('/api/v1/logs', json=event(message='Denied [audit]')).json()
    db.log_events.update_one({'_id': existing['id']}, {'$set': {'_search_index': 'siem-events'}})
    db.elastic_sync_state.insert_one({'_id': 'log_events'})
    batch = {'events': [
        event(message='denied [AUDIT]'),
        event(source='dns', message='denied [audit]'),
        event(message='denied audit'),
        event(level='INFO', message='denied [audit]'),
        event(timestamp='2020-01-01T00:00:00Z', message='denied [audit]'),
    ]}
    assert client.post('/api/v1/ingestion/batches', json=batch).json()['inserted'] == 5

    filters = {'q': '[audit]', 'source': 'firewall', 'level': 'WARNING'}
    response = client.get('/api/v1/search/events', params={**filters, 'limit': 1}).json()
    assert response['engine'] == 'mongodb'
    assert response['total'] == 2 and len(response['items']) == 1
    other_page = client.get('/api/v1/search/events', params={**filters, 'limit': 1, 'offset': 1}).json()
    rows = response['items'] + other_page['items']
    assert len({row['id'] for row in rows}) == 2
    assert existing['id'] in {row['id'] for row in rows}
    assert all('_search_index' not in row for row in rows)
    assert db.log_events.find_one({'_id': existing['id']})['_search_index'] == 'siem-events'
    assert db.elastic_sync_state.count_documents({}) == 1

    response = client.get('/api/v1/dashboard/charts', params={**filters, 'interval': 'day'}).json()
    assert response['event_count'] == 2 and response['interval'] == 'day'
    assert response['levels'] == [{'level': 'WARNING', 'count': 2}]
    assert response['top_sources'] == [{'source': 'firewall', 'count': 2}]
    assert sum(row['count'] for row in response['series']) == 2
    assert client.get('/api/v1/dashboard/charts', params={'q': 'not found'}).json()['series'] == []
    assert client.get('/api/v1/search/events', params={'q': '.*'}).json()['total'] == 0
    assert client.get('/api/v1/search/events', params={'start': '2020-01-01T00:00:00Z'}).status_code == 422
    window = {'start': '2020-01-02T00:00:00Z', 'end': '2020-01-01T00:00:00Z'}
    assert client.get('/api/v1/dashboard/charts', params=window).status_code == 422
