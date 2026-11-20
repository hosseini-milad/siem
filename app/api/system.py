from fastapi import APIRouter, Request, Response

from app.api.system_log_ml import TAG as SYSTEM_LOG_ML_TAG
from app.db.session import DB
from app.models.log import RETENTION_SECONDS
from app.services.access import SECTIONS, allowed
from app.services.agent_ingestion import AGENT_LOGS
from app.services.system_log_ml import AGENT_LOG_LABELS

router = APIRouter(prefix='/api/v1')

MENUS = (
    ('overview', 'نمای کلی', ('Overview',)),
    ('ingestion', 'ورود و پردازش', ('Ingestion', 'Logs')),
    ('events', 'جست‌وجوی رویدادها', ('Search',)),
    ('alerts', 'هشدارها', ('Alerts',)),
    ('analytics', 'تحلیل هوشمند', ('Datasets', 'Normalization', 'Standardization', 'Machine Learning', SYSTEM_LOG_ML_TAG['name'])),
    ('system', 'سامانه', ('System', 'Health')),
)

TAG_DESCRIPTIONS = {
    'Overview': 'داشبورد، نمودارها و شاخص‌های عملیاتی',
    'Ingestion': 'دریافت تکرارپذیر و وضعیت پردازش گروه لاگ',
    'Logs': 'ثبت و مشاهدهٔ رویدادها',
    'Search': 'جست‌وجو و فیلتر رویدادها در MongoDB',
    'Detection Rules': 'تعریف و ارزیابی قواعد شمارشی',
    'Alerts': 'ثبت و بررسی هشدارها',
    'Incidents': 'مدیریت رخدادهای امنیتی و یادداشت‌ها',
    'Datasets': 'ورود و مشاهدهٔ دادهٔ آموزشی',
    'Normalization': 'نرمال‌سازی ویژگی‌های اصلی',
    'Standardization': 'ساخت ویژگی‌های رفتاری استاندارد',
    'Machine Learning': 'آموزش، ارزیابی و پیش‌بینی',
    'System': 'منو، تنظیمات و وضعیت مؤلفه‌ها',
    'Health': 'سلامت اتصال MongoDB',
    SYSTEM_LOG_ML_TAG['name']: SYSTEM_LOG_ML_TAG['description'],
}

OPENAPI_TAGS = [{'name': tag, 'description': TAG_DESCRIPTIONS[tag]}
                for tag in [*(tag for _, _, tags in MENUS for tag in tags), 'Detection Rules', 'Incidents']]


@router.get('/system/navigation', tags=['System'], summary='منوی پنل و ترتیب تگ‌های Swagger')
def navigation(request: Request, response: Response):
    user = getattr(request.state, 'siem_user', None)
    menus = [{'id': key, 'label': label, 'tags': tags} for key, label, tags in MENUS]
    if user:
        response.headers['Cache-Control'] = 'no-store'
        for key, parent in (('explorer', 'events'), ('current-model', 'analytics'), ('systems', 'system'),
                            ('device-health', 'system'), ('users', 'system')):
            index = next(i for i, menu in enumerate(menus) if menu['id'] == parent)
            menus.insert(index + 1, {'id': key, 'label': SECTIONS[key], 'parent': parent, 'tags': []})
        if allowed(user, 'alerts'):
            index = next(i for i, menu in enumerate(menus) if menu['id'] == 'alerts')
            menus.insert(index + 1, {'id': 'alert-thresholds', 'label': 'تنظیم آستانه‌ها',
                                     'parent': 'alerts', 'tags': []})
        menus.extend([
            {'id': 'tasks', 'label': SECTIONS['tasks'], 'tags': ['Tasks']},
            {'id': 'task-columns', 'label': SECTIONS['task-columns'], 'parent': 'tasks', 'tags': []},
        ])
        menus = [menu for menu in menus if (menu['id'] in {'tasks', 'alert-thresholds'} or allowed(user, menu['id'])) and
                 (menu['id'] not in {'users', 'task-columns'} or user['role'] != 'client')]
    return {
        'authentication': request.app.state.settings.auth_required,
        'agents_in_scope': False,
        'dashboard_path': '/dashboard',
        'menus': menus,
    }


@router.get('/system/settings', tags=['System'], summary='مشاهدهٔ تنظیمات غیرمحرمانهٔ سامانه')
def settings(request: Request):
    return request.app.state.settings.model_dump(include={
        'mongodb_database', 'mongodb_server_selection_timeout_ms', 'mongodb_connect_timeout_ms',
        'mongodb_socket_timeout_ms', 'datasets_root', 'system_log_datasets_root', 'ml_model_dir', 'ml_threads',
    })


@router.get('/system/status', tags=['System'], summary='وضعیت اتصال MongoDB و آمادگی مدل')
def status(request: Request, database: DB):
    database.command('ping')
    return {
        'mongodb': {'available': True},
        'machine_learning': {'available': model_available(request.app.state.ml)},
    }


def model_available(manager):
    try:
        manager.require()
    except LookupError:
        return False
    return True


@router.get('/system/pipelines', tags=['System'], summary='سلامت و شاخص‌های مسیر شبکه و سیستم‌ها')
def pipelines(request: Request, database: DB):
    database.command('ping')
    latest_event = database.log_events.find_one(
        {}, {'received_at': 1}, sort=[('received_at', -1)])
    latest_agent = database[AGENT_LOGS].find_one(
        {}, {'received_at': 1}, sort=[('received_at', -1)])
    return {
        'database_available': True,
        'retention_days': RETENTION_SECONDS // 86400,
        'network': {
            'model_ready': model_available(request.app.state.ml),
            'dataset_records': database.dataset_records.estimated_document_count(),
            'standardized_records': database.standard_records.estimated_document_count(),
            'predictions': database.ml_predictions.estimated_document_count(),
            'last_received_at': (latest_event or {}).get('received_at'),
        },
        'system': {
            'model_ready': model_available(request.app.state.system_log_ml),
            'agent_logs': database[AGENT_LOGS].estimated_document_count(),
            'labeled_logs': database[AGENT_LOG_LABELS].estimated_document_count(),
            'registered_systems': database.systems.estimated_document_count(),
            'last_received_at': (latest_agent or {}).get('received_at'),
        },
    }

@router.get('/health', tags=['Health'], summary='بررسی اتصال دیتابیس')
def health(database: DB):
    database.command('ping')
    return {'status': 'ok', 'database': 'mongodb'}
