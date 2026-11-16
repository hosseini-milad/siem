from pathlib import Path
from uuid import UUID, uuid4
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.logs import DB
from app.services.datasets import archives, folder_path, import_folder

router = APIRouter(prefix='/api/v1/datasets', tags=['Datasets'])


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    folder: str = Field(min_length=1, max_length=255, examples=['Benign'])


@router.get('/folders', summary='فهرست پوشه‌های قابل انتخاب')
def folders(request: Request):
    root = Path(request.app.state.settings.datasets_root)
    if not root.is_dir():
        raise HTTPException(503, 'Dataset root unavailable on backend host; configure SIEM_DATASETS_ROOT')
    return {'folders': sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink())}


@router.post('/imports', status_code=202, summary='شروع ذخیره CSV پوشه انتخاب‌شده در MongoDB')
def start_import(body: ImportRequest, request: Request, tasks: BackgroundTasks, database: DB):
    root = Path(request.app.state.settings.datasets_root)
    if not root.is_dir():
        raise HTTPException(503, 'Dataset root unavailable on backend host; configure SIEM_DATASETS_ROOT')
    try:
        archives(folder_path(root, body.folder))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not request.app.state.import_lock.acquire(blocking=False):
        raise HTTPException(409, 'Another import is running')
    job_id = str(uuid4())
    try:
        database.dataset_imports.insert_one({'_id': job_id, 'folder': body.folder, 'status': 'running',
                                            'processed': 0, 'inserted': 0, 'created_at': datetime.now(timezone.utc)})
    except Exception:
        request.app.state.import_lock.release()
        raise

    def run():
        try:
            import_folder(database, root, body.folder, job_id)
        finally:
            request.app.state.import_lock.release()
    tasks.add_task(run)
    return {'id': job_id, 'status': 'running'}


@router.get('/imports/{import_id}', summary='وضعیت و شمارنده‌های ورود داده')
def import_status(import_id: UUID, database: DB):
    row = database.dataset_imports.find_one({'_id': str(import_id)})
    if row is None:
        raise HTTPException(404, 'Import not found')
    return {'id': row.pop('_id'), **row}


@router.get('/records', summary='مشاهده ردیف‌های ذخیره‌شدهٔ دیتاست')
def records(database: DB, folder: str = Query(min_length=1), limit: int = Query(50, ge=1, le=100),
            offset: int = Query(0, ge=0, le=100000)):
    query = {'folder': folder}
    rows = database.dataset_records.find(query).sort('_id', 1).skip(offset).limit(limit)
    return {'items': [{'id': row.pop('_id'), **row} for row in rows],
            'total': database.dataset_records.count_documents(query), 'limit': limit, 'offset': offset}
