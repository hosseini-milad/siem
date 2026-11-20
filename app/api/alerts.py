from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request

from app.db.session import DB
from app.schemas.siem import AlertCreate, AlertStatus, AlertUpdate, PredictionAlerts, Severity, SystemAlertCreate, SystemAlertSettings, WebAlertSettings
from app.services import alerts as service
from app.services import siem, system_alerts, web_alerts

AlertDomain = Literal['network', 'system', 'web']

router = APIRouter(prefix='/api/v1')


@router.post('/alerts', tags=['Alerts'], status_code=201, summary='ثبت هشدار دستی با شواهد معتبر')
def create_alert(body: AlertCreate, database: DB):
    try:
        ids = siem.require_links(database.log_events, body.event_ids)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    identity = str(uuid4())
    service.emit_alert(database, identity, {**body.model_dump(exclude_none=True), 'event_ids': ids, 'kind': 'manual'})
    return siem.public(database.siem_alerts.find_one({'_id': identity}))


@router.get('/alerts', tags=['Alerts'], summary='فهرست و فیلتر هشدارها')
def alerts(database: DB, status: AlertStatus | None = None, severity: Severity | None = None,
           domain: AlertDomain | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
    query = {key: value for key, value in {'status': status, 'severity': severity}.items() if value}
    return siem.page(database.siem_alerts, {**service.domain_filter(domain), **query}, limit, offset)


@router.get('/alerts/summary', tags=['Alerts'], summary='روند و شدت هشدارها')
def summary(database: DB, domain: AlertDomain, days: int = Query(7, ge=1, le=30)):
    return service.alert_summary(database, domain, days)


@router.post('/alerts/from-system-log', tags=['Alerts'], summary='ثبت هشدار از لاگ برچسب‌خوردهٔ سیستم')
def system_alert(body: SystemAlertCreate, database: DB):
    row = service.alert_from_system_log(database, body)
    if row is None:
        raise HTTPException(404, 'Labeled system log not found')
    return row


@router.post('/alerts/from-predictions', tags=['Alerts'], summary='تبدیل پیش‌بینی‌های ذخیره‌شدهٔ ML به هشدار بدون تکرار')
def prediction_alerts(body: PredictionAlerts, database: DB):
    return service.alerts_from_predictions(database, body.min_probability, body.limit)


@router.get('/alerts/settings/web', tags=['Alerts'], response_model=WebAlertSettings,
            summary='خواندن آستانه‌های هشدار وب‌سرویس')
def web_settings(database: DB):
    return web_alerts.settings(database)


@router.put('/alerts/settings/web', tags=['Alerts'], response_model=WebAlertSettings,
            summary='ذخیرهٔ آستانه‌های هشدار وب‌سرویس')
def update_web_settings(body: WebAlertSettings, database: DB):
    values = body.model_dump(exclude_none=True)
    database[web_alerts.SETTINGS].update_one({'_id': 'default'}, {'$set': values}, upsert=True)
    return web_alerts.settings(database)


@router.post('/alerts/owasp/evaluate', tags=['Alerts'], summary='ارزیابی دادهٔ موجود با قواعد OWASP')
def evaluate_owasp(request: Request, database: DB, service: str | None = Query(None, max_length=64)):
    configured = request.app.state.settings.web_collector_keys
    if service is not None and service not in configured:
        raise HTTPException(404, 'Web collector is not registered')
    return web_alerts.evaluate_current(database, (service,) if service else tuple(configured),
                                       datetime.now(timezone.utc))


@router.get('/alerts/settings/system', tags=['Alerts'], response_model=SystemAlertSettings,
            summary='خواندن آستانه‌های هشدار Windows Security')
def system_settings(database: DB):
    return system_alerts.settings(database)


@router.put('/alerts/settings/system', tags=['Alerts'], response_model=SystemAlertSettings,
            summary='ذخیرهٔ آستانه‌های هشدار Windows Security')
def update_system_settings(body: SystemAlertSettings, database: DB):
    values = body.model_dump()
    database[system_alerts.SETTINGS].update_one({'_id': 'default'}, {'$set': values}, upsert=True)
    return values


@router.post('/alerts/system/evaluate', tags=['Alerts'], summary='ارزیابی لاگ موجود با قواعد Windows Security')
def evaluate_system(database: DB):
    return system_alerts.evaluate(database, datetime.now(timezone.utc))


@router.get('/alerts/{alert_id}', tags=['Alerts'])
def alert(alert_id: UUID, database: DB):
    row = siem.public(database.siem_alerts.find_one({'_id': str(alert_id)}))
    if row is None:
        raise HTTPException(404, 'Alert not found')
    return row


@router.get('/alerts/{alert_id}/evidence', tags=['Alerts'], summary='مشاهدهٔ داده‌های منبع هشدار')
def evidence(alert_id: UUID, database: DB):
    row = database.siem_alerts.find_one({'_id': str(alert_id)})
    if row is None:
        raise HTTPException(404, 'Alert not found')
    return {'items': service.alert_evidence(database, row)}


@router.patch('/alerts/{alert_id}', tags=['Alerts'], summary='تأیید، بازکردن یا رفع هشدار')
def patch_alert(alert_id: UUID, body: AlertUpdate, database: DB):
    row = siem.update_status(database.siem_alerts, str(alert_id), body.status)
    if row is None:
        raise HTTPException(404, 'Alert not found')
    return row
