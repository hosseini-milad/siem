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


def test_branch_hierarchy_and_system_profiles(application):
    manager, app = application
    login(manager, 'manager')
    operators = []
    endpoints = []
    for branch in ('east', 'west'):
        registered = manager.post('/api/v1/users', json={
            'username': branch, 'name': branch, 'password': PASSWORD, 'branch': branch,
            'permissions': {'users': 'write', 'device-health': 'write'},
        })
        assert registered.status_code == 201, registered.text
        operator = TestClient(app, base_url='https://testserver')
        assert login(operator, branch).status_code == 200
        operators.append(operator)
        created = operator.post('/api/v1/users', json={
            'username': branch + '-host', 'name': 'Host', 'password': PASSWORD,
            'system': {'ip': '2001:0DB8::1', 'mac': 'AA-BB-CC-DD-EE-FF', 'type': 'server'},
        })
        assert created.status_code == 201, created.text
        endpoints.append(created.json()['id'])
        assert created.json()['system']['ip'] == '2001:db8::1'
        assert created.json()['system']['mac'] == 'aa:bb:cc:dd:ee:ff'

    east, west = endpoints
    operator = operators[0]
    assert operator.patch('/api/v1/auth/branch', json={'branch': 'Eastern office'}).status_code == 200
    assert [row['id'] for row in operator.get('/api/v1/users').json()['items']] == [east]
    assert [row['id'] for row in operator.get('/api/v1/device-health').json()['items']] == [east]
    profile = {'name': 'Host A', 'ip': '192.0.2.1', 'type': 'server', 'threshold': 75}
    assert operator.patch(f'/api/v1/device-health/{west}', json=profile).status_code == 404
    assert operator.patch(f'/api/v1/users/{west}', json={'name': 'Unauthorized'}).status_code == 404
    invalid = operator.patch(f'/api/v1/device-health/{east}', json={**profile, 'mac': 'invalid'})
    assert invalid.status_code == 422
    assert operator.patch(f'/api/v1/device-health/{east}', json=profile).status_code == 200
    assert operator.patch(f'/api/v1/users/{east}', json={'name': 'Updated', 'username': 'new-host'}).status_code == 200
    rows = {row['id']: row for row in manager.get('/api/v1/device-health').json()['items']}
    assert rows[east]['branch'] == 'Eastern office' and rows[west]['branch'] == 'west'
    assert rows[east]['system']['threshold'] == 75 and rows[east]['username'] == 'new-host'
    assert manager.patch(f'/api/v1/users/{east}', json={'permissions': {'device-health': 'read'}}).status_code == 200
    client = TestClient(app, base_url='https://testserver')
    assert login(client, 'new-host').status_code == 200
    assert [row['id'] for row in client.get('/api/v1/device-health').json()['items']] == [east]
    assert client.patch(f'/api/v1/device-health/{east}', json=profile).status_code == 403


def test_task_assignment_and_column_visibility(application):
    manager, app = application
    assert manager.get('/api/v1/tasks/boards').status_code == 401
    login(manager, 'manager')
    admins = []
    clients = []
    for branch in ('east', 'west'):
        created = manager.post('/api/v1/users', json={
            'username': branch, 'name': branch, 'password': PASSWORD, 'branch': branch,
            'permissions': {'tasks': 'write', 'task-columns': 'write', 'users': 'write'},
        })
        admin_id = created.json()['id']
        admin = TestClient(app, base_url='https://testserver')
        assert login(admin, branch).status_code == 200
        admins.append((admin_id, admin))
        for member in ('one', 'two') if branch == 'east' else ('three',):
            created = admin.post('/api/v1/users', json={
                'username': member, 'name': member, 'password': PASSWORD, 'system': {},
            })
            client_id = created.json()['id']
            assert manager.patch('/api/v1/users/' + client_id, json={'permissions': {'tasks': 'write'}}).status_code == 200
            client = TestClient(app, base_url='https://testserver')
            assert login(client, member).status_code == 200
            clients.append((client_id, client))
    (east_id, east), (west_id, west) = admins
    (one_id, one), (two_id, two), (three_id, three) = clients
    assert manager.post('/api/v1/tasks', json={'title': 'invalid', 'assignees': [one_id]}).status_code == 422
    assert one.post('/api/v1/tasks', json={'title': 'invalid', 'assignees': [three_id]}).status_code == 422
    assert one.get('/api/v1/task-columns').status_code == 403
    assert west.get('/api/v1/tasks', params={'board': east_id}).status_code == 404
    central = manager.post('/api/v1/tasks', json={'title': 'Central', 'assignees': [east_id, west_id]})
    assert central.status_code == 201, central.text
    central_path = '/api/v1/tasks/' + central.json()['id']
    assert [row['id'] for row in east.get(central_path).json()['assignees']] == [east_id]
    assert east.patch(central_path, json={'revision': 0, 'assignees': [one_id]}).status_code == 403
    assert one.get(central_path).status_code == 404

    branch_task = east.post('/api/v1/tasks', json={'title': 'Branch', 'assignees': [one_id], 'priority': 'high'})
    assert branch_task.status_code == 201, branch_task.text
    item = branch_task.json()
    path = '/api/v1/tasks/' + item['id']
    assert two.get(path).status_code == 404
    assert three.get(path).status_code == 404
    assert one.post('/api/v1/tasks', json={'title': 'Peer', 'assignees': [one_id, two_id]}).status_code == 201
    column = east.post('/api/v1/task-columns', json={'title': 'Review', 'position': 25, 'audience': 'branch'})
    assert column.status_code == 201, column.text
    column_id = column.json()['id']
    assert west.patch(f'/api/v1/task-columns/{column_id}',
                      json={'title': 'Bad', 'position': 20}).status_code == 404
    assert one.patch(path, json={'revision': 0, 'column_id': column_id}).status_code == 200
    assert two.get(path).status_code == 200
    assert three.get(path).status_code == 404
    column_path = '/api/v1/task-columns/' + column_id
    assert east.patch(column_path, json={'title': 'Review', 'position': 25,
                      'audience': 'selected', 'viewers': [three_id]}).status_code == 422
    assert east.patch(column_path, json={'title': 'Review', 'position': 25,
                      'audience': 'participants'}).status_code == 200
    assert two.get(path).status_code == 404
    assert east.patch(column_path, json={'title': 'Review', 'position': 25,
                      'audience': 'selected', 'viewers': [two_id]}).status_code == 200
    assert two.get(path).status_code == 200
    assert two.patch(path, json={'revision': 1, 'column_id': 'done'}).status_code == 403
    comment = two.post(path + '/comments', json={'text': 'Needs review'})
    assert comment.status_code == 201 and comment.json()['comments'][0]['author'] == 'two'
    assert east.patch(path, json={'revision': 0, 'column_id': 'doing'}).status_code == 409
    closed = one.patch(path, json={'revision': 1, 'column_id': 'done'})
    assert closed.status_code == 200 and closed.json()['closed_at']
    assert one.patch(path, json={'revision': 2, 'column_id': 'todo'}).status_code == 403
    page = manager.get('/api/v1/tasks', params={'board': east_id}).json()
    assert page['total'] == 2
    assert next(row for row in page['items'] if row['id'] == item['id'])['comment_count'] == 1
