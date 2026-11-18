from datetime import timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import AwareDatetime

from app.db.session import DB
from app.schemas.log import LogBatch, LogCreate, LogLevel, LogPage, LogRead
from app.services import logs

router = APIRouter(prefix="/api/v1/logs", tags=["Logs"])


@router.post("", response_model=LogRead, status_code=201, summary="ذخیره یک لاگ")
def create_log(event: LogCreate, database: DB):
    return logs.store_logs(database, [event])[0]


@router.post("/batch", response_model=list[LogRead], status_code=201, summary="ذخیره گروهی لاگ‌ها (۱ تا ۵۰۰)")
def create_batch(batch: LogBatch, database: DB):
    return logs.store_logs(database, batch.events)


@router.get("", response_model=LogPage, summary="مشاهده و فیلتر لاگ‌های ذخیره‌شده")
def get_logs(
    database: DB,
    source: str | None = Query(default=None, max_length=255),
    level: LogLevel | None = None,
    start: AwareDatetime | None = None,
    end: AwareDatetime | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
):
    if start is not None and end is not None and start > end:
        raise HTTPException(422, "start must be before or equal to end")
    return logs.list_logs(database, source=source, level=level,
                          start=start.astimezone(timezone.utc) if start else None,
                          end=end.astimezone(timezone.utc) if end else None,
                          limit=limit, offset=offset)


@router.get("/{log_id}", response_model=LogRead, summary="مشاهده لاگ با شناسه")
def get_log(log_id: UUID, database: DB):
    row = logs.find_log(database, str(log_id))
    if row is None:
        raise HTTPException(404, "Log not found")
    return row
