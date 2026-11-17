from datetime import datetime, timezone
import logging
import os
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request

from app.api.logs import DB
from app.services.standardization import standardize

logger = logging.getLogger('uvicorn.error.siem.standardization')

router = APIRouter(prefix='/api/v1/standardization', tags=['Standardization'])


@router.post('/runs', status_code=202, summary='افزودن ویژگی‌های رفتاری در بلوک‌های ۱۰۰۰۰ رکوردی')
def start(request: Request, tasks: BackgroundTasks, database: DB):
    if not request.app.state.import_lock.acquire(blocking=False):
        raise HTTPException(409, 'An import, normalization or standardization is already running')
    job_id = str(uuid4())
    try:
        database.standardization_runs.insert_one({'_id': job_id, 'status': 'running', 'phase': 'enrich',
            'processed': 0, 'blocks': 0, 'worker_pid': os.getpid(), 'created_at': datetime.now(timezone.utc)})
    except Exception:
        request.app.state.import_lock.release()
        raise

    def run():
        try:
            standardize(database, job_id)
        finally:
            request.app.state.import_lock.release()
    logger.info('Standardization %s accepted pid=%s; use this id to poll status', job_id, os.getpid())
    tasks.add_task(run)
    return {'id': job_id, 'status': 'running'}


@router.get('/runs/{run_id}', summary='وضعیت غنی‌سازی بلوکی')
def status(run_id: UUID, database: DB):
    row = database.standardization_runs.find_one({'_id': str(run_id)})
    if row is None:
        raise HTTPException(404, 'Standardization run not found')
    return row


@router.get('/records', summary='مشاهده داده‌های standard_records')
def records(database: DB, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=100000)):
    return {'items': list(database.standard_records.find().sort('_id', 1).skip(offset).limit(limit)),
            'total': database.standard_records.estimated_document_count(), 'limit': limit, 'offset': offset}
