from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import AwareDatetime

from app.api.logs import DB
from app.schemas.siem import (AlertCreate, AlertStatus, AlertUpdate, IncidentCreate, IncidentNote,
    IncidentStatus, IncidentUpdate, IngestionBatch, PredictionAlerts, RuleCreate, RuleToggle, Severity, SyncRequest)
from app.services import siem
from app.services.elk import IntegrationUnavailable

router = APIRouter(prefix='/api/v1')

TAGS = [
    ('Overview', 'نمای کلی و شاخص‌های عملیاتی SIEM'), ('Logs', 'رویدادها: ثبت، مشاهده و فیلتر در MongoDB'),
    ('Search', 'جست‌وجوی رویدادها در Elasticsearch'), ('Alerts', 'هشدارها: بررسی، تأیید و رفع هشدار'),
    ('Detection Rules', 'قواعد تشخیص ساختاریافته و ارزیابی آستانه‌ها'), ('Incidents', 'رخدادهای امنیتی و یادداشت بررسی'),
    ('Ingestion', 'ورود قابل تکرار از Logstash و پیگیری batch'), ('Elasticsearch', 'وضعیت، ایندکس و همگام‌سازی نمای جست‌وجو'),
    ('Logstash', 'وضعیت pipeline و ارسال JSON بدون اجنت'), ('Kibana', 'Data view و داشبوردهای Elasticsearch'),
    ('Machine Learning', 'تحلیل هوشمند: آموزش، ارزیابی و پیش‌بینی'), ('Datasets', 'ورود و مشاهدهٔ دادهٔ آموزشی'),
    ('Normalization', 'نرمال‌سازی ویژگی‌های اصلی'), ('Standardization', 'ساخت ویژگی‌های رفتاری استاندارد'),
    ('System', 'منوبندی و سلامت مؤلفه‌ها'), ('Health', 'سلامت اتصال MongoDB')]


@router.get('/system/navigation', tags=['System'], summary='منوبندی استاندارد پنل و تگ‌های Swagger')
def navigation():
    return {'authentication': False, 'agents_in_scope': False, 'menus': [
        {'id': 'overview', 'label': 'نمای کلی', 'tags': ['Overview']},
        {'id': 'events', 'label': 'رویدادها و جست‌وجو', 'tags': ['Logs', 'Search']},
        {'id': 'alerts', 'label': 'هشدارها', 'tags': ['Alerts']},
        {'id': 'detections', 'label': 'قواعد تشخیص', 'tags': ['Detection Rules']},
        {'id': 'incidents', 'label': 'رخدادهای امنیتی', 'tags': ['Incidents']},
        {'id': 'ingestion', 'label': 'ورود و پردازش', 'tags': ['Ingestion', 'Logstash']},
        {'id': 'analytics', 'label': 'تحلیل هوشمند', 'tags': ['Machine Learning', 'Datasets', 'Normalization', 'Standardization']},
        {'id': 'elk', 'label': 'مدیریت ELK', 'tags': ['Elasticsearch', 'Kibana']},
        {'id': 'system', 'label': 'سامانه', 'tags': ['System', 'Health']} ]}


@router.get('/system/status', tags=['System'], summary='سلامت MongoDB، مدل و سرویس‌های اختیاری ELK')
def status(request: Request, database: DB, include_elk: bool = False):
    database.command('ping')
    try:
        request.app.state.ml.require()
        model_ready = True
    except LookupError:
        model_ready = False
    return {'mongodb': {'available': True}, 'machine_learning': {'available': model_ready},
            'elk': [request.app.state.elk.status(name) for name in ('elasticsearch', 'logstash', 'kibana')] if include_elk else None}


@router.get('/overview', tags=['Overview'], summary='حجم رویداد، روند ساعتی، منابع، هشدارها و رخدادهای باز')
def overview(database: DB, hours: int = Query(24, ge=1, le=720)):
    return siem.overview(database, hours)


@router.post('/alerts', tags=['Alerts'], status_code=201, summary='ثبت هشدار دستی با شواهد معتبر')
def create_alert(body: AlertCreate, database: DB):
    try:
        ids = siem.require_links(database.log_events, body.event_ids)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return siem.create(database.siem_alerts, {**body.model_dump(), 'event_ids': ids, 'kind': 'manual', 'status': 'open'})


@router.get('/alerts', tags=['Alerts'], summary='فهرست و فیلتر هشدارها')
def alerts(database: DB, status: AlertStatus | None = None, severity: Severity | None = None,
           limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
    return siem.page(database.siem_alerts, {key: value for key, value in {'status': status, 'severity': severity}.items() if value}, limit, offset)


@router.post('/alerts/from-predictions', tags=['Alerts'], summary='تبدیل پیش‌بینی‌های ذخیره‌شدهٔ ML به هشدار بدون تکرار')
def prediction_alerts(body: PredictionAlerts, database: DB):
    return siem.alerts_from_predictions(database, body.min_probability, body.limit)


@router.get('/alerts/{alert_id}', tags=['Alerts'])
def alert(alert_id: UUID, database: DB):
    row = siem.public(database.siem_alerts.find_one({'_id': str(alert_id)}))
    if row is None:
        raise HTTPException(404, 'Alert not found')
    return row


@router.patch('/alerts/{alert_id}', tags=['Alerts'], summary='تأیید، بازکردن یا رفع هشدار')
def patch_alert(alert_id: UUID, body: AlertUpdate, database: DB):
    row = siem.update_status(database.siem_alerts, str(alert_id), body.status)
    if row is None:
        raise HTTPException(404, 'Alert not found')
    return row


@router.post('/detections/rules', tags=['Detection Rules'], status_code=201, summary='ساخت قاعدهٔ شمارش رویداد به تفکیک منبع')
def create_rule(body: RuleCreate, database: DB):
    return siem.create(database.siem_rules, body.model_dump())


@router.get('/detections/rules', tags=['Detection Rules'])
def rules(database: DB, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
    return siem.page(database.siem_rules, {}, limit, offset)


@router.put('/detections/rules/{rule_id}', tags=['Detection Rules'], summary='ویرایش تعریف قاعده')
def replace_rule(rule_id: UUID, body: RuleCreate, database: DB):
    result = database.siem_rules.update_one({'_id': str(rule_id)}, {'$set': {**body.model_dump(), 'updated_at': siem.now()}})
    if not result.matched_count:
        raise HTTPException(404, 'Rule not found')
    return siem.public(database.siem_rules.find_one({'_id': str(rule_id)}))


@router.patch('/detections/rules/{rule_id}', tags=['Detection Rules'], summary='فعال یا غیرفعال‌کردن قاعده')
def toggle_rule(rule_id: UUID, body: RuleToggle, database: DB):
    result = database.siem_rules.update_one({'_id': str(rule_id)}, {'$set': {'enabled': body.enabled, 'updated_at': siem.now()}})
    if not result.matched_count:
        raise HTTPException(404, 'Rule not found')
    return siem.public(database.siem_rules.find_one({'_id': str(rule_id)}))


@router.post('/detections/evaluate', tags=['Detection Rules'], summary='ارزیابی دستی قواعد فعال و تولید هشدار با کنترل تکرار')
def evaluate(database: DB):
    return siem.evaluate_rules(database)


@router.post('/incidents', tags=['Incidents'], status_code=201, summary='ثبت پروندهٔ بررسی و اتصال هشدارها')
def create_incident(body: IncidentCreate, database: DB):
    try:
        ids = siem.require_links(database.siem_alerts, body.alert_ids)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return siem.create(database.siem_incidents, {**body.model_dump(), 'alert_ids': ids, 'notes': [], 'status': 'open'})


@router.get('/incidents', tags=['Incidents'])
def incidents(database: DB, status: IncidentStatus | None = None, limit: int = Query(50, ge=1, le=200),
              offset: int = Query(0, ge=0, le=100000)):
    return siem.page(database.siem_incidents, {'status': status} if status else {}, limit, offset)


@router.get('/incidents/{incident_id}', tags=['Incidents'])
def incident(incident_id: UUID, database: DB):
    row = siem.public(database.siem_incidents.find_one({'_id': str(incident_id)}))
    if row is None:
        raise HTTPException(404, 'Incident not found')
    return row


@router.patch('/incidents/{incident_id}', tags=['Incidents'], summary='تغییر وضعیت بررسی رخداد')
def patch_incident(incident_id: UUID, body: IncidentUpdate, database: DB):
    row = siem.update_status(database.siem_incidents, str(incident_id), body.status)
    if row is None:
        raise HTTPException(404, 'Incident not found')
    return row


@router.post('/incidents/{incident_id}/notes', tags=['Incidents'], summary='ثبت یادداشت بررسی')
def note(incident_id: UUID, body: IncidentNote, database: DB):
    result = database.siem_incidents.update_one({'_id': str(incident_id), 'notes.99': {'$exists': False}}, {
        '$push': {'notes': {'text': body.text, 'created_at': siem.now()}}, '$set': {'updated_at': siem.now()}})
    if not result.matched_count:
        if not database.siem_incidents.find_one({'_id': str(incident_id)}):
            raise HTTPException(404, 'Incident not found')
        raise HTTPException(409, 'Incident note limit (100) reached')
    return siem.public(database.siem_incidents.find_one({'_id': str(incident_id)}))


@router.post('/ingestion/logstash', tags=['Ingestion'], summary='دریافت تکرارپذیر batch از pipeline لاگستش')
def receive(body: IngestionBatch, database: DB):
    try:
        return siem.receive_batch(database, body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get('/ingestion/batches/{batch_id}', tags=['Ingestion'], summary='وضعیت رسیدن batch لاگستش به MongoDB')
def batch_status(batch_id: UUID, database: DB):
    row = database.ingestion_batches.find_one({'_id': str(batch_id)}, {'fingerprint': 0})
    if row is None:
        raise HTTPException(404, 'Batch has not reached this API')
    return siem.public(row)


@router.get('/elasticsearch/status', tags=['Elasticsearch'])
def elastic_status(request: Request):
    return request.app.state.elk.status('elasticsearch')


@router.post('/elasticsearch/setup', tags=['Elasticsearch'], summary='ساخت ایندکس SIEM با نگاشت رویدادها')
def elastic_setup(request: Request, database: DB):
    result = request.app.state.elk.ensure_index()
    if result['created']:
        database.log_events.update_many({}, {'$unset': {'_search_index': ''}})
    return result


@router.post('/elasticsearch/sync', tags=['Elasticsearch'], summary='همگام‌سازی محدود و قابل تکرار از MongoDB')
def elastic_sync(body: SyncRequest, request: Request, database: DB):
    if not request.app.state.search_sync_lock.acquire(blocking=False):
        raise HTTPException(409, 'Search synchronization is running')
    try:
        return request.app.state.elk.sync(database, body.limit)
    finally:
        request.app.state.search_sync_lock.release()


@router.get('/elasticsearch/sync', tags=['Elasticsearch'], summary='آخرین وضعیت همگام‌سازی')
def elastic_sync_status(request: Request, database: DB):
    return {'state': database.elastic_sync_state.find_one({'_id': 'log_events'}),
            'pending': database.log_events.count_documents({'_search_index': {'$ne': request.app.state.settings.elasticsearch_index}})}


@router.get('/search/events', tags=['Search'], summary='جست‌وجوی متن و فیلتر رویدادها در Elasticsearch')
def search(request: Request, q: str = Query('', max_length=1024), source: str | None = Query(None, max_length=255),
           level: str | None = Query(None, pattern='^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$'),
           start: AwareDatetime | None = None, end: AwareDatetime | None = None,
           limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=10000)):
    if offset + limit > 10000:
        raise HTTPException(422, 'offset plus limit must not exceed the Elasticsearch result window of 10000')
    until = end or datetime.now(timezone.utc)
    since = start or until - timedelta(hours=24)
    if since > until:
        raise HTTPException(422, 'start must be before or equal to end')
    return request.app.state.elk.search(query=q, source=source, level=level, start=since, end=until, limit=limit, offset=offset)


@router.get('/logstash/status', tags=['Logstash'])
def logstash_status(request: Request):
    return request.app.state.elk.status('logstash')


@router.get('/logstash/pipelines', tags=['Logstash'], summary='آمار واقعی pipelineهای Logstash')
def pipelines(request: Request):
    result = request.app.state.elk.request('logstash', 'GET', '/_node/stats/pipelines')
    return {'pipelines': {name: {'events': data.get('events', {}), 'queue': data.get('queue', {})}
                           for name, data in result.get('pipelines', {}).items()}}


@router.post('/logstash/ingest', tags=['Logstash'], status_code=202, summary='ارسال batch آزمایشی به Logstash و پیگیری تحویل')
def send_logstash(body: IngestionBatch, request: Request, database: DB):
    try:
        identity = siem.prepare_batch(database, body, 'queued')
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    database.ingestion_batches.update_one({'_id': identity, 'status': {'$ne': 'stored'}},
                                         {'$set': {'status': 'queued', 'updated_at': siem.now()}})
    try:
        request.app.state.elk.request('logstash_input', 'POST', '', json=body.model_dump(mode='json'), decode=False)
    except IntegrationUnavailable:
        database.ingestion_batches.update_one({'_id': identity, 'status': {'$ne': 'stored'}},
                                             {'$set': {'status': 'delivery_failed', 'updated_at': siem.now()}})
        raise
    return {'batch_id': identity, 'status': 'accepted_by_logstash',
            'poll': '/api/v1/ingestion/batches/' + identity}


@router.get('/kibana/status', tags=['Kibana'])
def kibana_status(request: Request):
    return request.app.state.elk.status('kibana')


@router.post('/kibana/setup', tags=['Kibana'], summary='ساخت data view و داشبورد SIEM با شناسه‌های ثابت')
def kibana_setup(request: Request):
    return request.app.state.elk.bootstrap_kibana()


@router.get('/kibana/dashboards', tags=['Kibana'], summary='داشبوردهای واقعی ذخیره‌شده در Kibana')
def dashboards(request: Request):
    result = request.app.state.elk.request('kibana', 'GET', '/api/saved_objects/_find?type=dashboard&per_page=100')
    return {'items': [{'id': row['id'], 'title': row.get('attributes', {}).get('title')}
                      for row in result.get('saved_objects', [])], 'total': result.get('total', 0)}


@router.get('/detections/rules/{rule_id}', tags=['Detection Rules'])
def rule(rule_id: UUID, database: DB):
    row = siem.public(database.siem_rules.find_one({'_id': str(rule_id)}))
    if row is None:
        raise HTTPException(404, 'Rule not found')
    return row


@router.get('/elasticsearch/index', tags=['Elasticsearch'], summary='تعداد اسناد و حجم ایندکس جست‌وجوی SIEM')
def index_stats(request: Request):
    name = request.app.state.settings.elasticsearch_index
    result = request.app.state.elk.request('elasticsearch', 'GET', '/' + name + '/_stats/docs,store')
    primary = result['indices'][name]['primaries']
    return {'index': name, 'documents': primary['docs']['count'], 'size_bytes': primary['store']['size_in_bytes']}


@router.post('/elasticsearch/reset-sync', tags=['Elasticsearch'], summary='درخواست بازخوانی همهٔ رویدادها برای ایندکس؛ بدون حذف داده')
def reset_sync(request: Request, database: DB):
    if not request.app.state.search_sync_lock.acquire(blocking=False):
        raise HTTPException(409, 'Search synchronization is running')
    try:
        result = database.log_events.update_many({}, {'$unset': {'_search_index': ''}})
        database.elastic_sync_state.delete_one({'_id': 'log_events'})
        return {'queued': result.matched_count, 'next_action': 'POST /api/v1/elasticsearch/sync'}
    finally:
        request.app.state.search_sync_lock.release()
