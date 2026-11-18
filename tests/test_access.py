from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.services.access import COOKIE, password_hash, token_digest

PASSWORD = 'test-passphrase-123'


@pytest.fixture
def application(tmp_path):
    settings = Settings(auth_required=True, mongodb_database='siem_test_' + uuid4().hex,
                        ml_model_dir=str(tmp_path))
    app = create_app(settings)
    with TestClient(app, base_url='https://testserver') as client:
        database = app.state.database
        database.users.insert_one({'_id': 'manager', 'username': 'manager', 'name': 'Manager',
                                   'active': True, 'role': 'manager', 'session_version': 0,
                                   'password': password_hash(PASSWORD)})
        try:
            yield client, app
        finally:
            database.client.drop_database(settings.mongodb_database)


def login(client, username):
    return client.post('/api/v1/auth/login', json={'username': username, 'password': PASSWORD})


def test_roles_grants_and_session_revocation(application):
    manager, app = application
    admin = TestClient(app, base_url='https://testserver')
    client = TestClient(app, base_url='https://testserver')
    assert manager.get('/api/v1/health').status_code == 200
    assert manager.get('/api/v1/overview').status_code == 401
    assert manager.get('/dashboard').status_code == 401
    assert manager.get('/api/v1/system/navigation').status_code == 401
    assert manager.post('/api/v1/auth/login', json={'username': 'manager', 'password': 'x'},
                        headers={'Origin': 'https://foreign.example'}).status_code == 403
    signed_in = login(manager, 'manager')
    assert signed_in.status_code == 200, signed_in.text
    assert 'HttpOnly' in signed_in.headers['set-cookie'] and 'Secure' in signed_in.headers['set-cookie']
    assert manager.get('/api/v1/auth/me').json()['role'] == 'manager'
    assert manager.get('/api/v1/overview').status_code == 200
    admin_data = {'username': 'operator', 'name': 'Operator', 'password': PASSWORD,
                  'permissions': {'users': 'write', 'alerts': 'read'}}
    invalid = manager.post('/api/v1/users', json={**admin_data, 'password': 'short-test'})
    assert invalid.status_code == 422 and 'short-test' not in invalid.text
    created = manager.post('/api/v1/users', json=admin_data)
    assert created.status_code == 201, created.text
    assert 'password' not in created.json()
    assert created.json()['role'] == 'admin'
    assert login(admin, 'operator').status_code == 200
    assert admin.get('/api/v1/alerts').status_code == 200
    assert admin.post('/api/v1/alerts/from-predictions').status_code == 403
    assert admin.get('/api/v1/logs').status_code == 403
    assert admin.get('/api/v1/explorer/records').status_code == 403
    assert {row['id'] for row in admin.get('/api/v1/system/navigation').json()['menus']} == {'users', 'alerts'}
    payload = {'username': 'endpoint', 'name': 'Endpoint', 'password': PASSWORD, 'device_id': 'soc'}
    assert admin.post('/api/v1/users', json={**payload, 'permissions': {'system': 'write'}}).status_code == 403
    assert admin.post('/api/v1/users', json={**payload, 'device_id': None}).status_code == 422
    registered = admin.post('/api/v1/users', json=payload)
    assert registered.status_code == 201, registered.text
    assert registered.json()['role'] == 'client'
    assert admin.post('/api/v1/users', json={**payload, 'username': 'endpoint-2'}).status_code == 409
    target = '/api/v1/users/' + registered.json()['id']
    assert login(client, 'endpoint').status_code == 200
    assert client.get('/api/v1/users').status_code == 403
    assert client.get('/api/v1/system/navigation').json()['menus'] == []
    assert manager.patch(target, json={'permissions': {'device-health': 'write'}}).status_code == 404
    assert admin.patch(target, json={'permissions': {'device-health': 'read'}}).status_code == 403
    assert manager.patch(target, json={'permissions': {'device-health': 'read'}}).status_code == 200
    assert [row['id'] for row in client.get('/api/v1/system/navigation').json()['menus']] == ['device-health']
    assert admin.patch(target, json={'active': False}).status_code == 200
    assert client.get('/api/v1/auth/me').status_code == 401
    assert login(client, 'endpoint').status_code == 401
    assert manager.patch(target, json={'active': True}).status_code == 200
    assert client.get('/api/v1/auth/me').status_code == 401
    assert login(client, 'endpoint').status_code == 200
    token = client.cookies.get(COOKIE)
    assert app.state.database.sessions.find_one({'_id': token_digest(token)})
    assert client.post('/api/v1/auth/logout').status_code == 200
    assert not app.state.database.sessions.find_one({'_id': token_digest(token)})
    assert client.get('/api/v1/auth/me').status_code == 401
