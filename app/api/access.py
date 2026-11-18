import re
import secrets
from ipaddress import ip_address
from datetime import timedelta
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.db.session import DB
from app.services.access import (COOKIE, SECTIONS, SESSION_SECONDS, allowed, has_task_assignment, now,
                                 password_hash, password_matches, public_user, token_digest)

router = APIRouter(prefix='/api/v1', tags=['Access'])
Username = Annotated[str, Field(min_length=3, max_length=64, pattern=r'^[A-Za-z0-9_.-]+$')]
Password = Annotated[SecretStr, Field(min_length=12, max_length=128)]
Section = Literal['overview', 'ingestion', 'events', 'explorer', 'detections', 'alerts', 'incidents',
                  'analytics', 'current-model', 'system', 'device-health', 'users', 'tasks', 'task-columns']
Grants = dict[Section, Literal['read', 'write']]

PUBLIC = {'/api/v1/health', '/api/v1/auth/login', '/api/v1/auth/logout'}
SESSION_ONLY = {'/api/v1/auth/me', '/api/v1/auth/branch', '/api/v1/system/navigation'}
EXACT = {
    '/dashboard': 'overview',
    '/api/v1/ml/model': 'current-model',
    '/api/v1/ml/predict': 'current-model',
    '/api/v1/ml/predict-matrix': 'current-model',
}
PREFIX = {
    'overview': 'overview', 'dashboard': 'overview', 'logs': 'ingestion', 'ingestion': 'ingestion',
    'search': 'events', 'explorer': 'explorer', 'detections': 'detections', 'alerts': 'alerts',
    'incidents': 'incidents', 'datasets': 'analytics', 'normalization': 'analytics',
    'standardization': 'analytics', 'ml': 'analytics', 'system': 'system', 'users': 'users', 'device-health': 'device-health', 'tasks': 'tasks', 'task-columns': 'task-columns',
}


def get_user(request: Request):
    token = request.cookies.get(COOKIE, '')
    if not 1 <= len(token) <= 64:
        raise HTTPException(401, 'وارد حساب کاربری شوید.')
    database = request.app.state.database
    session = database.sessions.find_one({'_id': token_digest(token), 'expires_at': {'$gt': now()}})
    user = session and database.users.find_one({'_id': session['user_id'], 'active': True,
                                               'session_version': session['session_version']})
    if not user:
        raise HTTPException(401, 'نشست معتبر نیست. دوباره وارد شوید.')
    return user


def authorize(request: Request):
    path = request.scope['route'].path
    protected = path == '/dashboard' or path.startswith('/api/v1/')
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
    user = get_user(request)
    request.state.siem_user = user
    if path in SESSION_ONLY:
        return
    section = EXACT.get(path) or PREFIX.get(path.removeprefix('/api/v1/').split('/')[0])
    if section == 'tasks' and 'tasks' not in user.get('permissions', {}) and user['role'] != 'manager':
        if has_task_assignment(request.app.state.database, user):
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


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: Name | None = None
    username: Username | None = None
    branch: Name | None = None
    system: SystemProfile | None = None
    active: bool | None = None
    permissions: Grants | None = None


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
    return session_view(user, database)


@router.post('/auth/logout')
def logout(request: Request, response: Response, database: DB):
    token = request.cookies.get(COOKIE, '')
    if 1 <= len(token) <= 64:
        database.sessions.delete_one({'_id': token_digest(token)})
    response.delete_cookie(COOKIE, httponly=True,
                           secure=request.app.state.settings.session_cookie_secure, samesite='strict')
    return {'ok': True}


@router.get('/auth/me')
def me(user: User, response: Response, database: DB):
    response.headers['Cache-Control'] = 'no-store'
    return session_view(user, database)


def session_view(user, database):
    return {**public_user(user), 'task_access': allowed(user, 'tasks') or has_task_assignment(database, user)}


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
    return [public_user(row) | {
        'branch': branches.get(row.get('created_by'), '') if row['role'] == 'client' else row.get('branch', ''),
        'branch_id': row.get('created_by') if row['role'] == 'client' else row['_id'],
    } for row in rows]


def account_page(database, scope, limit, offset):
    rows = list(database.users.find(scope).sort([('created_by', 1), ('username', 1)]).skip(offset).limit(limit))
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
    if manager and (body.device_id or body.system is not None) or not manager and body.branch is not None:
        raise HTTPException(422, 'شاخه برای ادمین و مشخصات سیستم برای کلاینت تعریف می‌شود.')
    if not manager and body.system is None and not body.device_id:
        raise HTTPException(422, 'مشخصات سیستم یا شناسهٔ اتصال کلاینت را وارد کنید.')
    identity = uuid4().hex
    doc = {'_id': identity, 'username': body.username.lower(), 'name': body.name,
           'password': password_hash(body.password.get_secret_value()), 'role': 'admin' if manager else 'client',
           'permissions': body.permissions or {}, 'device_id': None if manager else body.device_id or identity,
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
    changes = body.model_dump(exclude_none=True)
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
    if not changes:
        raise HTTPException(422, 'تغییری برای ذخیره وارد نشده است.')
    update = {'$set': changes}
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
