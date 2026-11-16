from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request

from app.api.logs import DB
from app.services.normalization import normalize

router = APIRouter(prefix='/api/v1/normalization', tags=['Normalization'])


@router.post('/runs', status_code=202, summary='نرمال‌سازی کل dataset_records و جایگزینی normal_records')
def start(request: Request, tasks: BackgroundTasks, database: DB):
    if not request.app.state.import_lock.acquire(blocking=False):
        raise HTTPException(409, 'An import or normalization is already running')
    job_id = str(uuid4())
    try:
        database.normalization_runs.insert_one({'_id': job_id, 'status': 'running', 'phase': 'fit',
            'processed': 0, 'created_at': datetime.now(timezone.utc)})
    except Exception:
        request.app.state.import_lock.release()
        raise

    def run():
        try:
            normalize(database, job_id)
        finally:
            request.app.state.import_lock.release()
    tasks.add_task(run)
    return {'id': job_id, 'status': 'running'}


@router.get('/runs/{run_id}', summary='وضعیت اجرا و آمار Min-Max و نگاشت One-Hot')
def status(run_id: UUID, database: DB):
    row = database.normalization_runs.find_one({'_id': str(run_id)})
    if row is None:
        raise HTTPException(404, 'Normalization run not found')
    return row


@router.get('/records', summary='مشاهده داده‌های normal_records')
def records(database: DB, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=100000)):
    return {'items': list(database.normal_records.find().sort('_id', 1).skip(offset).limit(limit)),
            'total': database.normal_records.count_documents({}), 'limit': limit, 'offset': offset}
