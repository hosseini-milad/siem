from datetime import datetime, timezone
import logging
import os
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request

from app.api.logs import DB
from app.services.normalization import normalize
from app.services.standardization import standardize

logger = logging.getLogger('uvicorn.error.siem.standardization')

router = APIRouter(prefix='/api/v1/standardization', tags=['Standardization'])


@router.post('/runs', status_code=202, summary='افزودن ویژگی‌های رفتاری در بلوک‌های ۱۰۰۰۰ رکوردی')
def start(request: Request, tasks: BackgroundTasks, database: DB):
    if not request.app.state.import_lock.acquire(blocking=False):
        raise HTTPException(409, 'An import, normalization or standardization is already running')
    job_id = str(uuid4())
    try:
        database.standardization_runs.insert_one({'_id': job_id, 'status': 'running', 'phase': 'fit',
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


@router.post('/finalize', status_code=202, summary='نرمال‌سازی داده‌های جدید و ثبت برچسب نهایی در standard_records')
def finalize(request: Request, tasks: BackgroundTasks, database: DB):
    lock = request.app.state.import_lock
    if not lock.acquire(blocking=False):
        raise HTTPException(409, 'An import, normalization or standardization is already running')
    normalization_id, job_id = str(uuid4()), str(uuid4())
    stamp = datetime.now(timezone.utc)
    try:
        database.standardization_runs.insert_one({
            '_id': job_id, 'normalization_run_id': normalization_id, 'status': 'running',
            'phase': 'normalization', 'processed': 0, 'blocks': 0, 'worker_pid': os.getpid(),
            'created_at': stamp,
        })
    except Exception:
        lock.release()
        raise

    def run():
        try:
            database.normalization_runs.insert_one({
                '_id': normalization_id, 'status': 'running', 'phase': 'fit',
                'processed': 0, 'skipped': 0, 'scanned': 0, 'worker_pid': os.getpid(),
                'created_at': stamp,
            })
            normalize(database, normalization_id)
            result = database.normalization_runs.find_one({'_id': normalization_id})
            if result and result['status'] == 'completed':
                standardize(database, job_id)
            else:
                error = (result or {}).get('error', 'Normalization did not complete')
                database.standardization_runs.update_one({'_id': job_id}, {'$set': {
                    'status': 'failed', 'error': error, 'finished_at': datetime.now(timezone.utc),
                }})
        except Exception:
            logger.exception('Finalization %s failed', job_id)
            database.standardization_runs.update_one({'_id': job_id}, {'$set': {
                'status': 'failed', 'error': 'Finalization failed; see server logs',
                'finished_at': datetime.now(timezone.utc),
            }})
        finally:
            lock.release()

    tasks.add_task(run)
    return {'id': job_id, 'normalization_run_id': normalization_id, 'status': 'running'}


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
