from datetime import datetime, timezone
import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import AwareDatetime, TypeAdapter, ValidationError
from starlette.concurrency import run_in_threadpool

from app.db.session import DB
from app.schemas.log import LogBatch, LogCreate, LogLevel, LogPage, LogRead
from app.services import logs
from app.services.agent_ingestion import ingest_agent_payload
from app.services.raw_logs import parse_raw_log

router = APIRouter(prefix="/api/v1/logs", tags=["Logs"])
http_ingestion_router = APIRouter(tags=["Logs"])
MAX_HTTP_LOG_BYTES = 2 * 1024 * 1024
TIMESTAMP = TypeAdapter(AwareDatetime)
LEVEL_ALIASES = {"WARN": LogLevel.WARNING, "FATAL": LogLevel.CRITICAL}


def agent_json_event(payload, request: Request) -> LogCreate:
    received_at = datetime.now(timezone.utc)
    source_ip = request.client.host if request.client else "http-agent"
    source_port = request.client.port if request.client else None
    attributes = {"transport": "HTTP", "protocol": "TCP", "agent_payload": payload,
                  "source_ip": source_ip}
    if source_port is not None:
        attributes["source_port"] = source_port

    source = source_ip
    timestamp = received_at
    level = LogLevel.INFO
    message = "Agent JSON payload"
    if isinstance(payload, dict):
        candidate_source = next((payload.get(key) for key in
                                 ("source", "hostname", "host", "device_name", "agent_id")
                                 if payload.get(key) is not None), None)
        if candidate_source is not None:
            source = str(candidate_source).strip()[:255] or source_ip

        candidate_message = next((payload.get(key) for key in
                                  ("message", "msg", "event_message", "description")
                                  if payload.get(key) is not None), None)
        if candidate_message is not None:
            message = str(candidate_message).strip()[:65536] or message
        elif isinstance(payload.get("logs"), list):
            message = f"Agent payload with {len(payload['logs'])} log(s)"

        candidate_level = next((payload.get(key) for key in ("level", "severity")
                                if payload.get(key) is not None), None)
        if candidate_level is not None:
            level_name = str(candidate_level).strip().upper()
            try:
                level = LEVEL_ALIASES[level_name] if level_name in LEVEL_ALIASES else LogLevel(level_name)
            except ValueError:
                attributes["agent_level"] = candidate_level

        candidate_timestamp = next((payload.get(key) for key in
                                    ("timestamp", "collected_at", "created_at", "time")
                                    if payload.get(key) is not None), None)
        if candidate_timestamp is not None:
            try:
                timestamp = TIMESTAMP.validate_python(candidate_timestamp).astimezone(timezone.utc)
            except (ValidationError, ValueError, OverflowError):
                attributes["agent_timestamp"] = candidate_timestamp
    elif isinstance(payload, list):
        message = f"Agent JSON batch with {len(payload)} item(s)"

    return LogCreate(timestamp=timestamp, source=source, level=level,
                     message=message, attributes=attributes)


@http_ingestion_router.post("/logs", response_model=LogRead, status_code=201,
                            summary="دریافت یک لاگ از طریق HTTP")
async def receive_http_log(request: Request, database: DB):
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_HTTP_LOG_BYTES:
            raise HTTPException(413, "Log body must be at most 2 MiB")
        body.extend(chunk)

    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    agent_payload = None
    try:
        if media_type == "application/json":
            try:
                event = LogCreate.model_validate_json(body)
            except ValidationError:
                agent_payload = json.loads(body)
                event = agent_json_event(agent_payload, request)
        else:
            message = body.decode("utf-8").strip()
            if not 1 <= len(message) <= 65536:
                raise HTTPException(422, "Log message must contain 1 to 65536 characters")
            source = request.client.host if request.client else "http"
            attributes = {"transport": "HTTP", "protocol": "TCP"}
            if request.client:
                attributes.update(source_ip=source, source_port=request.client.port)
            event = parse_raw_log(message, source, datetime.now(timezone.utc), attributes)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(422, "Expected UTF-8 log text or a valid JSON log") from exc

    if isinstance(agent_payload, dict):
        source_ip = request.client.host if request.client else "http-agent"
        source_port = request.client.port if request.client else None
        nested = await run_in_threadpool(
            ingest_agent_payload, database, agent_payload, source_ip, source_port, datetime.now(timezone.utc),
        )
        return (await run_in_threadpool(logs.store_logs, database, [event, *nested]))[0]
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
