import re
import secrets
from io import BytesIO
from ipaddress import ip_address
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from PIL import Image, ImageOps
from starlette.concurrency import run_in_threadpool
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.db.session import DB
from app.services.access import (COOKIE, SECTIONS, SESSION_SECONDS, allowed, now,
                                 password_hash, password_matches, public_user, token_digest)

router = APIRouter(prefix='/api/v1', tags=['Access'])
Username = Annotated[str, Field(min_length=3, max_length=64, pattern=r'^[A-Za-z0-9_.-]+$')]
Password = Annotated[SecretStr, Field(min_length=12, max_length=128)]
Section = Literal['overview', 'ingestion', 'events', 'explorer', 'detections', 'alerts', 'incidents',
                  'analytics', 'current-model', 'system', 'systems', 'device-health', 'users', 'tasks', 'task-columns']
Grants = dict[Section, Literal['read', 'write']]

PUBLIC = {'/api/v1/health', '/api/v1/auth/login', '/api/v1/auth/logout'}
SESSION_ONLY = {'/api/v1/auth/me', '/api/v1/auth/branch', '/api/v1/auth/avatar', '/api/v1/auth/avatars/{token}', '/api/v1/system/navigation'}
EXACT = {
    '/dashboard': 'overview',
    '/logs': 'ingestion',
    '/api/v1/ml/model': 'current-model',
    '/api/v1/system-log-ml/models/current': 'current-model',
    '/api/v1/ml/predict': 'current-model',
    '/api/v1/ml/predict-matrix': 'current-model',
}
PREFIX = {
    'overview': 'overview', 'dashboard': 'overview', 'logs': 'ingestion', 'ingestion': 'ingestion',
    'search': 'events', 'explorer': 'explorer', 'detections': 'detections', 'alerts': 'alerts',
    'incidents': 'incidents', 'datasets': 'analytics', 'system-log-datasets': 'analytics',
    'system-log-ml': 'analytics', 'normalization': 'analytics',
    'standardization': 'analytics', 'ml': 'analytics', 'system': 'system', 'systems': 'systems',
    'users': 'users', 'device-health': 'device-health', 'tasks': 'tasks', 'task-columns': 'task-columns',
}


def get_user(request: Request):
    token = request.cookies.get(COOKIE, '')
    if not 1 <= len(token) <= 64:
        raise HTTPException(401, 'وارد حساب کاربری شوید.')
    database = request.app.state.database
    session = database.sessions.find_one({'_id': token_digest(token), 'expires_at': {'$gt': now()}})
    user = session and database.users.find_one({'_id': session['user_id'], 'active': True,
                                               'session_version': session['session_version']}, {'avatar_data': 0})
    if not user:
        raise HTTPException(401, 'نشست معتبر نیست. دوباره وارد شوید.')
    return user


def authorize(request: Request):
    path = request.scope['route'].path
    protected = path in {'/dashboard', '/logs'} or path.startswith('/api/v1/')
    if not protected:
        return
    write = request.method not in {'GET', 'HEAD', 'OPTIONS'}
    origin = request.headers.get('origin')
    host = request.headers.get('host')
    if write and (request.headers.get('sec-fetch-site') == 'cross-site' or
                  (origin is not None and origin not in {f'http://{host}', f'https://{host}'})):
        raise HTTPException(403, 'مبدأ درخواست مجاز نیست.')
    if path in PUBLIC or not request.app.state.settings.auth_required:
        return
    if path == '/logs' and request.method == 'POST':
        token = request.app.state.settings.http_log_token
        scheme, _, supplied = request.headers.get('authorization', '').partition(' ')
        if token and supplied and scheme.lower() == 'bearer' and secrets.compare_digest(
            supplied.encode(), token.get_secret_value().encode(),
        ):
            return
    user = get_user(request)
    request.state.siem_user = user
    if path in SESSION_ONLY:
        return
    section = EXACT.get(path) or PREFIX.get(path.removeprefix('/api/v1/').split('/')[0])
    if path == '/api/v1/system-log-ml/models/current' and allowed(user, 'analytics', write):
        return
    if section == 'tasks':
        return
    if not section or not allowed(user, section, write):
        raise HTTPException(403, 'دسترسی به این بخش یا عملیات مجاز نیست.')


def current_user(request: Request):
    return getattr(request.state, 'siem_user', None) or get_user(request)


User = Annotated[dict, Depends(current_user)]


class Login(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: Username
    password: Annotated[SecretStr, Field(min_length=1, max_length=128)]


Text = Annotated[str, Field(max_length=100)]
Name = Annotated[str, Field(min_length=1, max_length=100)]


class SystemProfile(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: Text = ''
    ip: Annotated[str, Field(max_length=45)] = ''
    mac: Annotated[str, Field(max_length=17)] = ''
    type: Literal['desktop', 'laptop', 'server', 'other'] = 'desktop'
    os: Text = ''
    processor: Text = ''
    memory: Text = ''
    storage: Text = ''
    threshold: int = Field(default=70, ge=1, le=100)

    @field_validator('ip')
    @classmethod
    def normalize_ip(cls, value):
        if '%' in value:
            raise ValueError('IP scope identifiers are unsupported')
        return str(ip_address(value)) if value else ''

    @field_validator('mac')
    @classmethod
    def normalize_mac(cls, value):
        if not value:
            return ''
        if not re.fullmatch(r'[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}', value, re.I):
            raise ValueError('Invalid MAC address')
        digits = value.lower().replace(':', '').replace('-', '')
        return ':'.join(digits[i:i+2] for i in range(0, 12, 2))


class BranchUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    branch: Name


class NewUser(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    username: Username
    name: str = Field(min_length=1, max_length=100)
    password: Password
    device_id: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{1,100}$')
    permissions: Grants | None = None
    branch: Name | None = None
    system: SystemProfile | None = None
    system_id: str | None = None

    @field_validator('system_id')
    @classmethod
    def valid_system_id(cls, value):
        return SystemProfile.normalize_mac(value) if value else None


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: Name | None = None
    username: Username | None = None
    branch: Name | None = None
    system: SystemProfile | None = None
    active: bool | None = None
    permissions: Grants | None = None
    system_id: str | None = None

    @field_validator('system_id')
    @classmethod
    def valid_system_id(cls, value):
        return SystemProfile.normalize_mac(value) if value else None


def count_login_attempt(database, key, limit):
    instant = now()
    window = int(instant.timestamp()) // 300
    counter = database.login_attempts.find_one_and_update(
        {'_id': f'{window}:{key}'},
        {'$inc': {'count': 1}, '$setOnInsert': {'expires_at': instant + timedelta(minutes=10)}},
        upsert=True, return_document=ReturnDocument.AFTER)
    if counter['count'] > limit:
        raise HTTPException(429, 'تعداد تلاش‌ها زیاد است. چند دقیقه بعد دوباره امتحان کنید.')


@router.post('/auth/login')
def login(body: Login, request: Request, response: Response, database: DB):
    address = request.client.host if request.client else 'unknown'
    username = body.username.lower()
    count_login_attempt(database, f'ip:{address}', 30)
    count_login_attempt(database, f'user:{username}:{address}', 8)
    user = database.users.find_one({'username': username})
    if not password_matches(body.password.get_secret_value(), user and user['password']) or not user['active']:
        raise HTTPException(401, 'نام کاربری یا رمز عبور معتبر نیست.')
    previous = request.cookies.get(COOKIE, '')
    if 1 <= len(previous) <= 64:
        database.sessions.delete_one({'_id': token_digest(previous)})
    token = secrets.token_urlsafe(32)
    database.sessions.insert_one({'_id': token_digest(token), 'user_id': user['_id'],
        'session_version': user['session_version'], 'expires_at': now() + timedelta(seconds=SESSION_SECONDS)})
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True,
                        secure=request.app.state.settings.session_cookie_secure, samesite='strict')
    response.headers['Cache-Control'] = 'no-store'
    return session_view(user)


@router.post('/auth/logout')
def logout(request: Request, response: Response, database: DB):
    token = request.cookies.get(COOKIE, '')
    if 1 <= len(token) <= 64:
        database.sessions.delete_one({'_id': token_digest(token)})
    response.delete_cookie(COOKIE, httponly=True,
                           secure=request.app.state.settings.session_cookie_secure, samesite='strict')
    return {'ok': True}


@router.get('/auth/me')
def me(user: User, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    return session_view(user)


def avatar_thumbnail(data):
    try:
        with Image.open(BytesIO(data), formats=['JPEG', 'PNG', 'WEBP']) as source:
            if source.width * source.height > 16_000_000 or max(source.size) > 8192:
                raise ValueError('Image dimensions too large')
            source.thumbnail((192, 192))
            image = ImageOps.exif_transpose(source).convert('RGBA')
            output = BytesIO()
            image.save(output, format='WEBP', quality=82)
            return output.getvalue()
    except (OSError, ValueError, Image.DecompressionBombError) as exc:
        raise HTTPException(422, 'تصویر معتبر JPEG، PNG یا WebP انتخاب کنید.') from exc


@router.put('/auth/avatar')
async def upload_avatar(request: Request, user: User, database: DB):
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > 2 * 1024 * 1024:
            raise HTTPException(413, 'حجم تصویر نباید بیشتر از ۲ مگابایت باشد.')
        data.extend(chunk)
    image = await run_in_threadpool(avatar_thumbnail, data)
    updated = await run_in_threadpool(
        database.users.find_one_and_update,
        {'_id': user['_id'], 'active': True, 'session_version': user['session_version']},
        {'$set': {'avatar_token': uuid4().hex, 'avatar_data': image}},
        projection={'avatar_data': 0}, return_document=ReturnDocument.AFTER)
    if not updated:
        raise HTTPException(401, 'نشست معتبر نیست.')
    return session_view(updated)


@router.get('/auth/avatars/{token}')
def get_avatar(token: Annotated[str, Field(pattern=r'^[a-f0-9]{32}$')], user: User, database: DB):
    avatar = database.users.find_one({'avatar_token': token}, {'avatar_data': 1})
    if not avatar:
        raise HTTPException(404, 'تصویر پیدا نشد.')
    return Response(avatar['avatar_data'], media_type='image/webp',
                    headers={'Cache-Control': 'private, max-age=3600', 'X-Content-Type-Options': 'nosniff'})


def session_view(user):
    return {**public_user(user), 'task_access': True}


def latest_metrics(database, system_ids):
    if not system_ids:
        return {}
    result = {}
    cursor = database.system_metrics.find(
        {'system_id': {'$in': list(system_ids)}}
    ).sort('received_at', -1)
    for row in cursor:
        result.setdefault(row['system_id'], row)
        if len(result) == len(system_ids):
            break
    return result


@router.patch('/auth/branch')
def update_branch(body: BranchUpdate, user: User, database: DB):
    if user['role'] != 'admin':
        raise HTTPException(403, 'فقط ادمین می‌تواند نام شاخهٔ خودش را تنظیم کند.')
    updated = database.users.find_one_and_update({'_id': user['_id'], 'role': 'admin'},
                                                 {'$set': {'branch': body.branch}},
                                                 return_document=ReturnDocument.AFTER)
    return public_user(updated)


def with_branches(database, rows):
    owners = {row.get('created_by') for row in rows if row['role'] == 'client'}
    branches = {owner['_id']: owner.get('branch', '') for owner in
                database.users.find({'_id': {'$in': list(owners)}, 'role': 'admin'}, {'branch': 1})} if owners else {}
    system_ids = {row.get('system_id') for row in rows if row.get('system_id')}
    systems = {row['_id']: row for row in database.systems.find({'_id': {'$in': list(system_ids)}})} if system_ids else {}
    metrics = latest_metrics(database, system_ids)
    result = [public_user(row) | {
        'branch': branches.get(row.get('created_by'), '') if row['role'] == 'client' else row.get('branch', ''),
        'branch_id': row.get('created_by') if row['role'] == 'client' else row['_id'],
    } for row in rows]
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    for account, source in zip(result, rows):
        system = systems.get(source.get('system_id'))
        if not system:
            continue
        current_metrics = metrics.get(system['_id'], {})
        stored_profile = source.get('system') or {}
        manual = {key: stored_profile[key] for key in ('name', 'ip', 'type', 'threshold')
                  if key in stored_profile and stored_profile[key] is not None and stored_profile[key] != ''}
        last_seen = current_metrics.get('received_at')
        account['system'] = {
            'id': system['_id'], 'mac': system['mac'], 'name': system.get('hostname') or system.get('agent_id'),
            'ip': system.get('source_ip', ''), 'type': system.get('type', 'desktop'),
            'os': ' '.join(filter(None, [system.get('os_name'), system.get('os_release'), system.get('os_version')])),
            'processor': system.get('processor', ''),
            'architecture': system.get('architecture', ''),
            'cpu_cores_physical': system.get('cpu_cores_physical'),
            'cpu_cores_logical': system.get('cpu_cores_logical'),
            'memory': f"{system['total_ram_gb']:g} GB" if isinstance(system.get('total_ram_gb'), (int, float)) else '',
            'storage': f"{system['total_disk_c_gb']:g} GB" if isinstance(system.get('total_disk_c_gb'), (int, float)) else '',
            'threshold': system.get('threshold', 70), 'last_seen': last_seen,
            'online': bool(last_seen and last_seen > cutoff),
            'cpu': current_metrics.get('cpu_percent'), 'ram': current_metrics.get('memory_percent'),
            'disk': current_metrics.get('disk_percent'), 'memory_used_mb': current_metrics.get('memory_used_mb'),
            'disk_read_bytes_per_sec': current_metrics.get('disk_read_bytes_per_sec'),
            'disk_write_bytes_per_sec': current_metrics.get('disk_write_bytes_per_sec'),
            'net_sent_bytes_per_sec': current_metrics.get('net_sent_bytes_per_sec'),
            'net_recv_bytes_per_sec': current_metrics.get('net_recv_bytes_per_sec'),
            **manual,
        }
    return result


def system_scope(user, database):
    if user['role'] == 'manager':
        return {}
    if user['role'] == 'admin':
        own = [row['system_id'] for row in database.users.find(
            {'role': 'client', 'created_by': user['_id'], 'system_id': {'$type': 'string'}}, {'system_id': 1})]
        assigned = [row['system_id'] for row in database.users.find(
            {'system_id': {'$type': 'string'}}, {'system_id': 1})]
        return {'$or': [{'_id': {'$in': own}}, {'_id': {'$nin': assigned}}]}
    return {'_id': user.get('system_id', '')}


@router.get('/systems')
def systems(user: User, database: DB, response: Response,
            limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
    if not allowed(user, 'systems'):
        raise HTTPException(403, 'دسترسی به فهرست سیستم‌ها مجاز نیست.')
    scope = system_scope(user, database)
    rows = list(database.systems.find(scope).sort([('hostname', 1), ('mac', 1)]).skip(offset).limit(limit))
    metrics = latest_metrics(database, {item['_id'] for item in rows})
    assignments = {row['system_id']: row for row in database.users.find(
        {'system_id': {'$in': [item['_id'] for item in rows]}}, {'name': 1, 'system_id': 1})}
    response.headers['Cache-Control'] = 'no-store'
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    return {'items': [{
        'id': row['_id'], 'mac': row['mac'], 'hostname': row.get('hostname') or row.get('agent_id'),
        'os': ' '.join(filter(None, [row.get('os_name'), row.get('os_release'), row.get('os_version')])),
        'architecture': row.get('architecture'), 'processor': row.get('processor'),
        'cpu_cores_physical': row.get('cpu_cores_physical'), 'cpu_cores_logical': row.get('cpu_cores_logical'),
        'total_ram_gb': row.get('total_ram_gb'), 'total_disk_c_gb': row.get('total_disk_c_gb'),
        'cpu_percent': metrics.get(row['_id'], {}).get('cpu_percent'),
        'memory_percent': metrics.get(row['_id'], {}).get('memory_percent'),
        'memory_used_mb': metrics.get(row['_id'], {}).get('memory_used_mb'),
        'disk_read_bytes_per_sec': metrics.get(row['_id'], {}).get('disk_read_bytes_per_sec'),
        'disk_write_bytes_per_sec': metrics.get(row['_id'], {}).get('disk_write_bytes_per_sec'),
        'net_sent_bytes_per_sec': metrics.get(row['_id'], {}).get('net_sent_bytes_per_sec'),
        'net_recv_bytes_per_sec': metrics.get(row['_id'], {}).get('net_recv_bytes_per_sec'),
        'source_ip': row.get('source_ip'), 'first_seen': row.get('first_seen'),
        'last_seen': metrics.get(row['_id'], {}).get('received_at'),
        'online': bool(metrics.get(row['_id'], {}).get('received_at') and
                       metrics[row['_id']]['received_at'] > cutoff),
        'assigned_user': ({'id': assignments[row['_id']]['_id'], 'name': assignments[row['_id']]['name']}
                          if row['_id'] in assignments else None),
    } for row in rows], 'total': database.systems.count_documents(scope), 'limit': limit, 'offset': offset}


def account_page(database, scope, limit, offset):
    rows = list(database.users.find(scope, {'avatar_data': 0}).sort([('created_by', 1), ('username', 1)]).skip(offset).limit(limit))
    return {'items': with_branches(database, rows), 'total': database.users.count_documents(scope),
            'limit': limit, 'offset': offset}


def device_scope(user):
    if user['role'] == 'manager':
        return {'role': 'client'}
    if user['role'] == 'admin':
        return {'role': 'client', 'created_by': user['_id']}
    return {'role': 'client', '_id': user['_id']}


@router.get('/device-health')
def device_health(user: User, database: DB, response: Response,
                  limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
    response.headers['Cache-Control'] = 'no-store'
    return account_page(database, device_scope(user), limit, offset)


@router.patch('/device-health/{user_id}')
def update_device(user_id: str, body: SystemProfile, user: User, database: DB):
    if user['role'] == 'client':
        raise HTTPException(403, 'ویرایش سیستم مجاز نیست.')
    updated = database.users.find_one_and_update(
        {'_id': user_id, **device_scope(user)}, {'$set': {'system': body.model_dump()}},
        return_document=ReturnDocument.AFTER)
    if not updated:
        raise HTTPException(404, 'سیستم پیدا نشد.')
    return with_branches(database, [updated])[0]


def account_scope(user):
    if user['role'] == 'manager':
        return {'role': {'$in': ['admin', 'client']}}
    if user['role'] == 'admin':
        return {'role': 'client', 'created_by': user['_id']}
    raise HTTPException(403, 'مدیریت حساب‌ها مجاز نیست.')


@router.get('/users')
def users(user: User, database: DB, response: Response,
          limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
    if not allowed(user, 'users'):
        raise HTTPException(403, 'دسترسی به کاربران مجاز نیست.')
    scope = account_scope(user)
    response.headers['Cache-Control'] = 'no-store'
    return account_page(database, scope, limit, offset)


@router.post('/users', status_code=201)
def create_user(body: NewUser, user: User, database: DB):
    account_scope(user)
    if not allowed(user, 'users', write=True):
        raise HTTPException(403, 'ایجاد کاربر مجاز نیست.')
    manager = user['role'] == 'manager'
    if not manager and body.permissions is not None:
        raise HTTPException(403, 'فقط مدیریت کل دسترسی‌ها را تعیین می‌کند.')
    if manager and (body.device_id or body.system is not None or body.system_id) or not manager and body.branch is not None:
        raise HTTPException(422, 'شاخه برای ادمین و مشخصات سیستم برای کلاینت تعریف می‌شود.')
    if not manager and body.system is None and not body.device_id and not body.system_id:
        raise HTTPException(422, 'مشخصات سیستم یا شناسهٔ اتصال کلاینت را وارد کنید.')
    if body.system_id:
        if not database.systems.find_one({'_id': body.system_id, **system_scope(user, database)}):
            raise HTTPException(404, 'سیستم انتخاب‌شده پیدا نشد.')
        if database.users.find_one({'system_id': body.system_id}):
            raise HTTPException(409, 'سیستم انتخاب‌شده به کاربر دیگری متصل است.')
    identity = uuid4().hex
    doc = {'_id': identity, 'username': body.username.lower(), 'name': body.name,
           'password': password_hash(body.password.get_secret_value()), 'role': 'admin' if manager else 'client',
           'permissions': body.permissions or {}, 'device_id': None if manager else body.device_id or identity,
           'system_id': None if manager else body.system_id,
           'active': True, 'session_version': 0, 'created_by': user['_id']}
    if manager:
        doc['branch'] = body.branch or ''
    elif body.system is not None:
        doc['system'] = body.system.model_dump()
    try:
        database.users.insert_one(doc)
    except DuplicateKeyError as exc:
        raise HTTPException(409, 'نام کاربری یا سیستم انتخاب‌شده قبلاً ثبت شده است.') from exc
    return public_user(doc)


@router.patch('/users/{user_id}')
def update_user(user_id: str, body: UserUpdate, user: User, database: DB):
    scope = account_scope(user)
    if not allowed(user, 'users', write=True):
        raise HTTPException(403, 'ویرایش حساب مجاز نیست.')
    if body.permissions is not None and user['role'] != 'manager':
        raise HTTPException(403, 'فقط مدیریت کل دسترسی‌ها را تعیین می‌کند.')
    changes = body.model_dump(exclude_none=True, exclude={'system_id'})
    if body.username is not None:
        changes['username'] = body.username.lower()
    requires_admin = body.branch is not None or (body.permissions is not None and (
        bool({'users', 'task-columns'} & body.permissions.keys()) or body.permissions.get('device-health') == 'write'))
    if requires_admin and (user['role'] != 'manager' or body.system is not None):
        raise HTTPException(403, 'تغییر شاخه یا این مجوزها برای این حساب مجاز نیست.')
    if requires_admin:
        scope = {'role': 'admin'}
    elif body.system is not None:
        scope['role'] = 'client'
    if 'system_id' in body.model_fields_set:
        scope['role'] = 'client'
    if not changes and 'system_id' not in body.model_fields_set:
        raise HTTPException(422, 'تغییری برای ذخیره وارد نشده است.')
    if body.system_id:
        if not database.systems.find_one({'_id': body.system_id, **system_scope(user, database)}):
            raise HTTPException(404, 'سیستم انتخاب‌شده پیدا نشد.')
        if database.users.find_one({'system_id': body.system_id, '_id': {'$ne': user_id}}):
            raise HTTPException(409, 'سیستم انتخاب‌شده به کاربر دیگری متصل است.')
        changes['system_id'] = body.system_id
    update = {'$set': changes}
    if 'system_id' in body.model_fields_set and body.system_id is None:
        update['$unset'] = {'system_id': ''}
    if body.active is False:
        update['$inc'] = {'session_version': 1}
    try:
        updated = database.users.find_one_and_update({'_id': user_id, **scope}, update,
                                                     return_document=ReturnDocument.AFTER)
    except DuplicateKeyError as exc:
        raise HTTPException(409, 'نام کاربری قبلاً ثبت شده است.') from exc
    if not updated:
        raise HTTPException(404, 'کاربر سازگار با این عملیات پیدا نشد.')
    return public_user(updated)
