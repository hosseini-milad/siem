"""Provision the first manager from a trusted terminal."""
from getpass import getpass

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

from app.api.access import Login
from app.core.config import Settings
from app.services.access import initialize_access, password_hash


def main():
    username = input('Manager username: ').strip().lower()
    name = input('Display name: ').strip()
    password = getpass('Password (12–128 characters): ')
    try:
        Login(username=username, password=password)
    except ValueError:
        raise SystemExit('Invalid username or password length.') from None
    if not 1 <= len(name) <= 100 or len(password) < 12:
        raise SystemExit('Enter a display name and a password of at least 12 characters.')
    if password != getpass('Confirm password: '):
        raise SystemExit('Passwords did not match.')
    settings = Settings()
    with MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=settings.mongodb_server_selection_timeout_ms) as client:
        database = client[settings.mongodb_database]
        initialize_access(database)
        try:
            database.users.insert_one({'_id': 'manager', 'username': username, 'name': name, 'role': 'manager',
                'password': password_hash(password), 'permissions': {}, 'active': True, 'session_version': 0})
        except DuplicateKeyError:
            raise SystemExit('The manager already exists or the username is taken.') from None
    print('Manager account created.')


if __name__ == '__main__':
    main()
