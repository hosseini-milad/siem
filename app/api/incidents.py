from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.db.session import DB
from app.schemas.siem import IncidentCreate, IncidentNote, IncidentStatus, IncidentUpdate
from app.services import siem

router = APIRouter(prefix='/api/v1')


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
