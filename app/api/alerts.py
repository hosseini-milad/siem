from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.db.session import DB
from app.schemas.siem import AlertCreate, AlertStatus, AlertUpdate, PredictionAlerts, Severity, SystemAlertCreate
from app.services import alerts as service
from app.services import siem

AlertDomain = Literal['network', 'system']

router = APIRouter(prefix='/api/v1')


@router.post('/alerts', tags=['Alerts'], status_code=201, summary='ثبت هشدار دستی با شواهد معتبر')
def create_alert(body: AlertCreate, database: DB):
    try:
        ids = siem.require_links(database.log_events, body.event_ids)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return siem.create(database.siem_alerts, {**body.model_dump(), 'event_ids': ids, 'kind': 'manual', 'status': 'open'})


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
