from fastapi import APIRouter, Request, Response

from app.db.session import DB
from app.services.access import SECTIONS, allowed

router = APIRouter(prefix='/api/v1')

MENUS = (
    ('overview', 'نمای کلی', ('Overview',)),
    ('ingestion', 'ورود و پردازش', ('Ingestion', 'Logs')),
    ('events', 'جست‌وجوی رویدادها', ('Search',)),
    ('detections', 'قواعد تشخیص', ('Detection Rules',)),
    ('alerts', 'هشدارها', ('Alerts',)),
    ('incidents', 'رخدادهای امنیتی', ('Incidents',)),
    ('analytics', 'تحلیل هوشمند', ('Datasets', 'Normalization', 'Standardization', 'Machine Learning')),
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
}

OPENAPI_TAGS = [{'name': tag, 'description': TAG_DESCRIPTIONS[tag]}
                for _, _, tags in MENUS for tag in tags]


@router.get('/system/navigation', tags=['System'], summary='منوی پنل و ترتیب تگ‌های Swagger')
def navigation(request: Request, response: Response):
    user = getattr(request.state, 'siem_user', None)
    menus = [{'id': key, 'label': label, 'tags': tags} for key, label, tags in MENUS]
    if user:
        response.headers['Cache-Control'] = 'no-store'
        for key, parent in (('explorer', 'events'), ('current-model', 'analytics'), ('device-health', 'system'), ('users', 'system')):
            index = next(i for i, menu in enumerate(menus) if menu['id'] == parent)
            menus.insert(index + 1, {'id': key, 'label': SECTIONS[key], 'parent': parent, 'tags': []})
        menus = [menu for menu in menus if allowed(user, menu['id']) and
                 (menu['id'] != 'users' or user['role'] != 'client')]
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
        'mongodb_socket_timeout_ms', 'datasets_root', 'ml_model_dir', 'ml_threads',
    })


@router.get('/system/status', tags=['System'], summary='وضعیت اتصال MongoDB و آمادگی مدل')
def status(request: Request, database: DB):
    database.command('ping')
    try:
        request.app.state.ml.require()
    except LookupError:
        model_ready = False
    else:
        model_ready = True
    return {'mongodb': {'available': True}, 'machine_learning': {'available': model_ready}}


@router.get('/health', tags=['Health'], summary='بررسی اتصال دیتابیس')
def health(database: DB):
    database.command('ping')
    return {'status': 'ok', 'database': 'mongodb'}
