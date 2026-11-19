from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.db.session import DB
from app.services.system_log_datasets import COLLECTION, JOBS, dataset_files, import_dataset, import_path

router = APIRouter(prefix="/api/v1/system-log-datasets", tags=["Datasets"])


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    path: str = Field(min_length=1, max_length=1024,
                      examples=[r"F:\PY\Server\SIEM\ds\OS\LMD-2023\Labelled LMD-2023"])


@router.post("/imports", status_code=202, summary="شروع ذخیرهٔ دیتاست لاگ سیستم در MongoDB")
def start_import(body: ImportRequest, request: Request, tasks: BackgroundTasks, database: DB):
    root = Path(request.app.state.settings.system_log_datasets_root)
    if not root.is_dir():
        raise HTTPException(503, "System-log dataset root unavailable; configure SIEM_SYSTEM_LOG_DATASETS_ROOT")
    try:
        selected = import_path(root, body.path)
        files = dataset_files(selected)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not request.app.state.import_lock.acquire(blocking=False):
        raise HTTPException(409, "Another import is running")
    job_id = str(uuid4())
    try:
        database[JOBS].insert_one({
            "_id": job_id, "path": str(selected), "status": "running", "file_count": len(files),
            "completed_files": 0, "processed": 0, "inserted": 0, "updated": 0,
            "created_at": datetime.now(timezone.utc),
        })
    except Exception:
        request.app.state.import_lock.release()
        raise

    def run():
        try:
            import_dataset(database, root, body.path, job_id)
        finally:
            request.app.state.import_lock.release()

    tasks.add_task(run)
    return {"id": job_id, "status": "running", "file_count": len(files)}


@router.get("/imports/{import_id}", summary="وضعیت ورود دیتاست لاگ سیستم")
def import_status(import_id: UUID, database: DB):
    row = database[JOBS].find_one({"_id": str(import_id)})
    if not row:
        raise HTTPException(404, "Import not found")
    return {"id": row.pop("_id"), **row}


@router.get("/records", summary="نمونهٔ رکوردهای دیتاست لاگ سیستم")
def imported_records(database: DB, limit: int = Query(20, ge=1, le=100),
                     offset: int = Query(0, ge=0, le=100000)):
    rows = list(database[COLLECTION].find().sort("_id", 1).skip(offset).limit(limit))
    return {"items": rows, "total": database[COLLECTION].count_documents({}),
            "limit": limit, "offset": offset}
