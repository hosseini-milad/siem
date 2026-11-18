from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.db.session import DB
from app.schemas.siem import AlertCreate, AlertStatus, AlertUpdate, PredictionAlerts, Severity
from app.services import alerts as service
from app.services import siem

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
           limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
    return siem.page(database.siem_alerts, {key: value for key, value in {'status': status, 'severity': severity}.items() if value}, limit, offset)


@router.post('/alerts/from-predictions', tags=['Alerts'], summary='تبدیل پیش‌بینی‌های ذخیره‌شدهٔ ML به هشدار بدون تکرار')
def prediction_alerts(body: PredictionAlerts, database: DB):
    return service.alerts_from_predictions(database, body.min_probability, body.limit)


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
