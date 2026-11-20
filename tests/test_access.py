from datetime import datetime, timedelta, timezone
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
    assert 'Max-Age=604800' in signed_in.headers['set-cookie']
    session = app.state.database.sessions.find_one({'_id': token_digest(manager.cookies[COOKIE])})
    remaining = session['expires_at'] - datetime.now(timezone.utc)
    assert timedelta(days=7, seconds=-5) < remaining <= timedelta(days=7)
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
    assert {row['id'] for row in admin.get('/api/v1/system/navigation').json()['menus']} == {'users', 'systems', 'alerts', 'tasks'}
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
    assert [row['id'] for row in client.get('/api/v1/system/navigation').json()['menus']] == ['tasks']
    assert manager.patch(target, json={'permissions': {'device-health': 'write'}}).status_code == 404
    assert admin.patch(target, json={'permissions': {'device-health': 'read'}}).status_code == 403
    assert manager.patch(target, json={'permissions': {'device-health': 'read'}}).status_code == 200
    assert [row['id'] for row in client.get('/api/v1/system/navigation').json()['menus']] == ['device-health', 'systems', 'tasks']
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


def test_discovered_system_can_be_assigned_and_supplies_live_health(application):
    manager, app = application
    login(manager, 'manager')
    manager.post('/api/v1/users', json={
        'username': 'operator', 'name': 'Operator', 'password': PASSWORD, 'branch': 'SOC',
        'permissions': {'users': 'write', 'device-health': 'write'},
    }).json()['id']
    mac = '78:24:af:cb:1b:fd'
    app.state.database.systems.insert_one({
        '_id': mac, 'mac': mac, 'agent_id': 'DESKTOP-88EQ9K3', 'hostname': 'DESKTOP-88EQ9K3',
        'os_name': 'Windows', 'os_release': '10', 'processor': 'Intel CPU', 'total_ram_gb': 15.89,
        'total_disk_c_gb': 159.88, 'source_ip': '127.0.0.1',
        'last_seen': datetime.now(timezone.utc),
    })
    app.state.database.system_metrics.insert_one({
        '_id': 'metric-1', 'system_id': mac, 'agent_id': 'DESKTOP-88EQ9K3',
        'cpu_percent': 7.71, 'memory_percent': 64.8, 'received_at': datetime.now(timezone.utc),
    })
    admin = TestClient(app, base_url='https://testserver')
    assert login(admin, 'operator').status_code == 200
    systems = admin.get('/api/v1/systems').json()['items']
    assert systems[0]['id'] == mac and systems[0]['assigned_user'] is None
    created = admin.post('/api/v1/users', json={
        'username': 'analyst', 'name': 'Analyst', 'password': PASSWORD, 'system_id': mac,
    })
    assert created.status_code == 201, created.text
    user_id = created.json()['id']
    assert admin.post('/api/v1/users', json={
        'username': 'other', 'name': 'Other', 'password': PASSWORD, 'system_id': mac,
    }).status_code == 409
    app.state.database.users.update_one({'_id': user_id}, {'$set': {'system': {
        'name': 'اتاق ۱۰۳', 'ip': '192.168.1.13', 'mac': '', 'os': '', 'processor': '',
        'memory': '', 'storage': '', 'type': 'desktop', 'threshold': 70,
    }}})
    account = admin.get('/api/v1/users').json()['items'][0]
    assert account['system_id'] == mac
    assert account['system']['name'] == 'اتاق ۱۰۳' and account['system']['ip'] == '192.168.1.13'
    assert account['system']['mac'] == mac and account['system']['os'] == 'Windows 10'
    assert account['system']['processor'] == 'Intel CPU'
    health = admin.get('/api/v1/device-health').json()['items'][0]
    assert health['id'] == user_id
    assert health['system']['online'] is True
    assert health['system']['cpu'] == 7.71 and health['system']['ram'] == 64.8
    listed = admin.get('/api/v1/systems').json()['items'][0]
    assert listed['mac'] == mac and listed['cpu_percent'] == 7.71
    assert listed['assigned_user']['id'] == user_id
    assert admin.patch(f'/api/v1/systems/{mac}', json={'hostname': 'changed'}).status_code == 404
    assert admin.patch(f'/api/v1/users/{user_id}', json={'system_id': None}).status_code == 200
    assert admin.get('/api/v1/users').json()['items'][0]['system_id'] is None


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

    branch_task = east.post('/api/v1/tasks', json={'title': 'Branch', 'assignees': [one_id], 'priority': 'high', 'tags': ['restricted']})
    assert branch_task.status_code == 201, branch_task.text
    item = branch_task.json()
    path = '/api/v1/tasks/' + item['id']
    assert {card['title'] for card in east.get('/api/v1/tasks').json()['items']} == {'Central', 'Branch'}
    assert {card['title'] for card in manager.get('/api/v1/tasks').json()['items']} == {'Central', 'Branch'}
    assert two.get(path).status_code == 404
    assert two.get('/api/v1/tasks', params={'board': east_id}).json()['tag_suggestions'] == []
    assert three.get(path).status_code == 404
    peer = one.post('/api/v1/tasks', json={'title': 'Peer', 'assignees': [two_id]})
    assert peer.status_code == 201
    assert one.get('/api/v1/tasks/' + peer.json()['id']).status_code == 200
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


def test_task_assignment_without_menu_privilege_and_expiration(application):
    from datetime import timedelta

    from app.services.access import now

    manager, app = application
    assert login(manager, 'manager').status_code == 200
    admin_id = manager.post('/api/v1/users', json={
        'username': 'worker', 'name': 'Admin', 'password': PASSWORD,
        'permissions': {'users': 'write', 'task-columns': 'write'},
    }).json()['id']
    admin = TestClient(app, base_url='https://testserver')
    assert login(admin, 'worker').status_code == 200
    endpoint = admin.post('/api/v1/users', json={
        'username': 'device', 'name': 'Client', 'password': PASSWORD, 'system': {},
    }).json()
    target = endpoint['id']
    path = '/api/v1/tasks'
    assert {item['id'] for item in admin.get(path, params={'board': admin_id}).json()['assignees']} == {target, admin_id}
    client = TestClient(app, base_url='https://testserver')
    assert login(client, 'device').json()['task_access'] is True
    assert client.get(path, params={'board': admin_id}).json()['can_create'] is True
    personal = client.post(path, json={'title': 'Personal', 'assignees': [target]})
    assert personal.status_code == 201, personal.text
    assert client.get(path, params={'board': admin_id}).json()['total'] == 1
    task = admin.post(path, json={'title': 'Review', 'assignees': [target], 'tags': [' Design ', 'design', 'new']})
    assert task.status_code == 201, task.text
    assert task.json()['tags'] == ['Design', 'new']
    item = path + '/' + task.json()['id']
    assert client.get('/api/v1/auth/me').json()['task_access'] is True
    assert client.get('/api/v1/system/navigation').json()['menus'][0]['id'] == 'tasks'
    assert client.get(item).json()['can_assign'] is True
    assert client.post(item + '/comments', json={'text': 'Seen'}).json()['updated_by'] == 'Client'
    assert admin.patch(item, json={'revision': 0, 'tags': ['review']}).json()['tags'] == ['review']
    assert client.patch(item, json={'revision': 1, 'assignees': [target], 'priority': 'high'}).status_code == 200
    assert client.patch(item, json={'revision': 2, 'column_id': 'done'}).status_code == 200
    assert admin.get(path, params={'board': admin_id}).json()['total'] == 1
    app.state.database.tasks.update_one({'_id': task.json()['id']}, {'$set': {'closed_at': now() - timedelta(days=1)}})
    page = admin.get(path, params={'board': admin_id}).json()
    assert page['total'] == 0
    assert [card['id'] for card in client.get(path).json()['items']] == [personal.json()['id']]
    assert admin.get(item).status_code == 404
    assert app.state.database.tasks.find_one({'_id': task.json()['id']}) is not None
    assert client.get('/api/v1/auth/me').json()['task_access'] is True


def test_avatar_and_independent_column_cursor(application):
    from io import BytesIO

    from PIL import Image

    manager, app = application
    assert login(manager, 'manager').status_code == 200
    raw = BytesIO()
    Image.new('RGB', (300, 100), 'green').save(raw, format='PNG')
    path = '/api/v1/auth/avatar'
    assert manager.put(path, content=b'<svg/>').status_code == 422
    assert manager.put(path, content=b'x' * (2 * 1024 * 1024 + 1)).status_code == 413
    uploaded = manager.put(path, content=raw.getvalue(), headers={'Content-Type': 'image/png'})
    assert uploaded.status_code == 200, uploaded.text
    url = uploaded.json()['avatar_url']
    assert manager.get('/api/v1/auth/me').json()['avatar_url'] == url
    image = manager.get(url)
    assert image.headers['content-type'] == 'image/webp'
    assert Image.open(BytesIO(image.content)).size == (192, 64)
    assert TestClient(app, base_url='https://testserver').get(url).status_code == 401

    path = '/api/v1/tasks'
    tasks = []
    for index in range(7):
        response = manager.post(path, json={'title': f'Item {index}', 'assignees': ['manager']})
        assert response.status_code == 201
        assert response.json()['assignees'][0]['avatar_url'] == url
        tasks.append(response.json()['id'])
    assert manager.patch(path + '/' + tasks[0], json={'revision': 0, 'column_id': 'doing'}).status_code == 200
    metadata = manager.get(path, params={'metadata_only': True}).json()
    assert metadata['items'] == [] and metadata['columns']
    params = {'column_id': 'todo', 'limit': 5}
    first = manager.get(path, params=params).json()
    assert len(first['items']) == 5 and first['total'] == 6
    second = manager.get(path, params={**params, 'before': first['next_cursor']}).json()
    assert second['next_cursor'] is None and len(second['items']) == 1
    assert {row['id'] for page in (first, second) for row in page['items']} == set(tasks[1:])
    running = manager.get(path, params={'column_id': 'doing', 'limit': 5}).json()
    assert [row['id'] for row in running['items']] == tasks[:1]
