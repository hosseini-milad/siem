import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from threading import BoundedSemaphore

SECTIONS = {
    'overview': 'نمای کلی', 'ingestion': 'ورود و پردازش', 'events': 'جست‌وجوی رویدادها',
    'explorer': 'کاوش داده‌ها', 'detections': 'قواعد تشخیص', 'alerts': 'هشدارها',
    'incidents': 'رخدادهای امنیتی', 'analytics': 'تحلیل هوشمند', 'current-model': 'مدل جاری',
    'system': 'سامانه', 'systems': 'سیستم‌ها', 'device-health': 'سلامت سیستم‌ها',
    'users': 'کاربران', 'tasks': 'تسک‌ها', 'task-columns': 'مدیریت ستون تسک‌ها',
}
COOKIE = 'siem_session'
SESSION_SECONDS = 8 * 60 * 60
password_slots = BoundedSemaphore(2)


def now():
    return datetime.now(timezone.utc)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    with password_slots:
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**17, r=8, p=1,
                                maxmem=192 * 1024**2)
    return {'salt': salt, 'digest': digest.hex()}


def password_matches(password, stored):
    candidate = password_hash(password, stored['salt'] if stored else '0' * 32)
    return hmac.compare_digest(candidate['digest'], stored['digest'] if stored else '0' * 128) and stored is not None


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def avatar_url(user):
    token = user.get('avatar_token')
    return f'/api/v1/auth/avatars/{token}' if token else None


def public_user(user):
    return {'id': user['_id'], **{key: user[key] for key in ('username', 'name', 'role', 'active')},
            'device_id': user.get('device_id'), 'system_id': user.get('system_id'),
            'permissions': user.get('permissions', {}),
            'branch': user.get('branch', ''), 'system': user.get('system'), 'avatar_url': avatar_url(user)}


def allowed(user, section, write=False):
    if user['role'] == 'manager':
        return True
    if section == 'systems':
        grants = user.get('permissions', {})
        return not write and any(grants.get(key) in {'read', 'write'} for key in ('systems', 'users', 'device-health'))
    grant = user.get('permissions', {}).get(section)
    return grant == 'write' or (not write and grant == 'read')


def visible_task_lifetime():
    return {'$or': [{'closed_at': None}, {'closed_at': {'$gt': now() - timedelta(days=1)}}]}


def initialize_access(database):
    database.users.create_index('username', unique=True)
    database.users.create_index('avatar_token', unique=True, sparse=True)
    database.users.create_index('device_id', unique=True, partialFilterExpression={'device_id': {'$type': 'string'}})
    database.users.create_index('system_id', unique=True, partialFilterExpression={'system_id': {'$type': 'string'}})
    database.users.create_index([('role', 1), ('created_by', 1), ('username', 1)])
    database.tasks.create_index([('board', 1), ('created_at', -1), ('_id', 1)])
    database.tasks.create_index([('column_id', 1), ('created_at', -1), ('_id', 1)])
    database.tasks.create_index([('assignees', 1), ('closed_at', 1)])
    database.task_columns.create_index('board')
    database.sessions.create_index('expires_at', expireAfterSeconds=0)
    database.login_attempts.create_index('expires_at', expireAfterSeconds=0)
