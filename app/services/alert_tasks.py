"""Route newly issued alerts to the existing task boards."""
import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from uuid import NAMESPACE_URL, uuid5

from pymongo.errors import DuplicateKeyError, PyMongoError
from starlette.concurrency import run_in_threadpool

BRANCHES = {'web': 'وب‌سرویس‌ها', 'network': 'شبکه', 'system': 'سیستم‌عامل'}
PRIORITIES = {'critical': 'urgent', 'high': 'high', 'medium': 'normal', 'low': 'low'}
LOGGER = logging.getLogger('uvicorn.error.siem.alert_tasks')


def branch_values(name):
    normalized = ' '.join(name.replace('\u200c', ' ').split()).casefold()
    domain = next((key for key, label in BRANCHES.items()
                   if normalized in (key, label.replace('\u200c', ' '))), None)
    return {'branch': BRANCHES[domain] if domain else name, 'alert_domain': domain}


def task_id(alert_id):
    return uuid5(NAMESPACE_URL, 'siem-alert-task:' + alert_id).hex


def active_owner(db, domain):
    owner = db.users.find_one({'role': 'admin', 'active': True, 'alert_domain': domain}, {'_id': 1})
    return owner['_id'] if owner else None


def deliver(db, alert):
    domain = alert.get('domain') or 'network'
    owner = active_owner(db, domain)
    identity = task_id(alert['_id'])
    evidence = alert.get('evidence') or {}
    details = {
        'id': alert['_id'], 'domain': domain, 'severity': alert['severity'],
        'source': alert['source'], 'created_at': alert['created_at'],
        'rule': evidence.get('rule') or alert.get('rule_id'),
        'category': alert.get('owasp_category'),
        'source_ip': evidence.get('source_ip'),
        'observed_count': evidence.get('observed_count', evidence.get('count')),
        'threshold': evidence.get('threshold'),
        'occurred_at': evidence.get('occurred_at'),
        'window_minutes': evidence.get('window_minutes'),
        'windows_event_id': evidence.get('windows_event_id'),
    }
    task = {
        'title': alert['title'][:120], 'description': alert['description'],
        'priority': PRIORITIES[alert['severity']], 'tags': ['هشدار', BRANCHES[domain]],
        'board': owner or 'central', 'assignees': [owner] if owner else [],
        'creator': None, 'updated_by': None, 'column_id': 'todo',
        'created_at': alert['created_at'], 'closed_at': None, 'comments': [],
        'comment_count': 0, 'revision': 0,
        'alert': {key: value for key, value in details.items() if value is not None},
        'routing_pending': owner is None,
    }
    try:
        db.tasks.update_one({'_id': identity}, {'$setOnInsert': task}, upsert=True)
    except DuplicateKeyError:
        if not db.tasks.find_one({'_id': identity}, {'_id': 1}):
            raise
    db.siem_alerts.update_one({'_id': alert['_id']}, {'$unset': {'task_pending': ''}})


def reconcile(db):
    for alert in db.siem_alerts.find({'task_pending': True}).limit(100):
        deliver(db, alert)
    for domain in BRANCHES:
        owner = active_owner(db, domain)
        if owner:
            db.tasks.update_many({
                'routing_pending': True, 'alert.domain': domain, 'board': 'central',
                'assignees': [], 'column_id': 'todo', 'closed_at': None,
            }, {'$set': {'board': owner, 'assignees': [owner], 'routing_pending': False},
                '$inc': {'revision': 1}})


@asynccontextmanager
async def monitor_alert_tasks(db):
    async def monitor():
        while True:
            try:
                await run_in_threadpool(reconcile, db)
            except PyMongoError:
                LOGGER.exception('Could not reconcile alert tasks')
            await asyncio.sleep(15)

    worker = asyncio.create_task(monitor())
    try:
        yield
    finally:
        worker.cancel()
        with suppress(asyncio.CancelledError):
            await worker
