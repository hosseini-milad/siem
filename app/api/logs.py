from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import AwareDatetime, ValidationError
from starlette.concurrency import run_in_threadpool

from app.db.session import DB
from app.schemas.log import LogBatch, LogCreate, LogLevel, LogPage, LogRead
from app.services import logs
from app.services.raw_logs import parse_raw_log

router = APIRouter(prefix="/api/v1/logs", tags=["Logs"])
http_ingestion_router = APIRouter(tags=["Logs"])
MAX_HTTP_LOG_BYTES = 2 * 1024 * 1024


@http_ingestion_router.post("/logs", response_model=LogRead, status_code=201,
                            summary="دریافت یک لاگ از طریق HTTP")
async def receive_http_log(request: Request, database: DB):
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_HTTP_LOG_BYTES:
            raise HTTPException(413, "Log body must be at most 2 MiB")
        body.extend(chunk)

    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    try:
        if media_type == "application/json":
            event = LogCreate.model_validate_json(body)
        else:
            message = body.decode("utf-8").strip()
            if not 1 <= len(message) <= 65536:
                raise HTTPException(422, "Log message must contain 1 to 65536 characters")
            source = request.client.host if request.client else "http"
            attributes = {"transport": "HTTP", "protocol": "TCP"}
            if request.client:
                attributes.update(source_ip=source, source_port=request.client.port)
            event = parse_raw_log(message, source, datetime.now(timezone.utc), attributes)
    except (UnicodeDecodeError, ValidationError) as exc:
        raise HTTPException(422, "Expected UTF-8 log text or a valid JSON log") from exc

    return (await run_in_threadpool(logs.store_logs, database, [event]))[0]


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
