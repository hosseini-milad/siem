import secrets
from datetime import timedelta
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.db.session import DB
from app.services.access import (COOKIE, SECTIONS, SESSION_SECONDS, allowed, now,
                                 password_hash, password_matches, public_user, token_digest)

router = APIRouter(prefix='/api/v1', tags=['Access'])
Username = Annotated[str, Field(min_length=3, max_length=64, pattern=r'^[A-Za-z0-9_.-]+$')]
Password = Annotated[SecretStr, Field(min_length=12, max_length=128)]
Section = Literal['overview', 'ingestion', 'events', 'explorer', 'detections', 'alerts', 'incidents',
                  'analytics', 'current-model', 'system', 'device-health', 'users']
Grants = dict[Section, Literal['read', 'write']]

PUBLIC = {'/api/v1/health', '/api/v1/auth/login', '/api/v1/auth/logout'}
SESSION_ONLY = {'/api/v1/auth/me', '/api/v1/system/navigation'}
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
    'standardization': 'analytics', 'ml': 'analytics', 'system': 'system', 'users': 'users',
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
    if not section or not allowed(user, section, write):
        raise HTTPException(403, 'دسترسی به این بخش یا عملیات مجاز نیست.')


def current_user(request: Request):
    return getattr(request.state, 'siem_user', None) or get_user(request)


User = Annotated[dict, Depends(current_user)]


class Login(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: Username
    password: Annotated[SecretStr, Field(min_length=1, max_length=128)]


class NewUser(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    username: Username
    name: str = Field(min_length=1, max_length=100)
    password: Password
    device_id: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{1,100}$')
    permissions: Grants | None = None


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
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
    return public_user(user)


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
    return public_user(user)


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
    items = database.users.find(scope).sort('username', 1).skip(offset).limit(limit)
    response.headers['Cache-Control'] = 'no-store'
    return {'items': [public_user(item) for item in items], 'total': database.users.count_documents(scope),
            'limit': limit, 'offset': offset}


@router.post('/users', status_code=201)
def create_user(body: NewUser, user: User, database: DB):
    account_scope(user)
    if not allowed(user, 'users', write=True):
        raise HTTPException(403, 'ایجاد کاربر مجاز نیست.')
    manager = user['role'] == 'manager'
    if not manager and body.permissions is not None:
        raise HTTPException(403, 'فقط مدیریت کل دسترسی‌ها را تعیین می‌کند.')
    if manager == bool(body.device_id):
        raise HTTPException(422, 'اتصال به سیستم فقط برای حساب کلاینت الزامی است.')
    doc = {'_id': uuid4().hex, 'username': body.username.lower(), 'name': body.name,
           'password': password_hash(body.password.get_secret_value()), 'role': 'admin' if manager else 'client',
           'permissions': body.permissions or {}, 'device_id': body.device_id,
           'active': True, 'session_version': 0, 'created_by': user['_id']}
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
    if not changes:
        raise HTTPException(422, 'تغییری برای ذخیره وارد نشده است.')
    update = {'$set': changes}
    if body.active is False:
        update['$inc'] = {'session_version': 1}
    if body.permissions is not None and ('users' in body.permissions or body.permissions.get('device-health') == 'write'):
        scope = {'role': 'admin'}
    updated = database.users.find_one_and_update({'_id': user_id, **scope}, update,
                                                 return_document=ReturnDocument.AFTER)
    if not updated:
        raise HTTPException(404, 'کاربر سازگار با این عملیات پیدا نشد.')
    return public_user(updated)
