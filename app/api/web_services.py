from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress, StringConstraints, ValidationError
from pymongo import UpdateOne
from pymongo.errors import DuplicateKeyError
from starlette.concurrency import run_in_threadpool

from app.db.session import DB
from app.services.web_access import INGEST_PATH, RECORDS

router = APIRouter(tags=['System'])
COLLECTION = 'web_service_batches'
RETENTION = 7 * 86400
MAX_BODY = 512 * 1024
HISTOGRAM_BOUNDS_MS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)
Counter = Annotated[int, Field(ge=0, le=1000000000)]
Source = Annotated[str, StringConstraints(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$')]


MediaType = Literal[
    'application/json', 'application/problem+json', 'application/x-www-form-urlencoded',
    'application/octet-stream', 'multipart/form-data', 'text/plain', 'text/html', 'text/css',
]
BodyField = Literal['id', 'batch_id', 'events', 'items', 'count', 'status', 'code', 'error', 'detail', 'limit', 'offset']


class HeaderMetadata(BaseModel):
    model_config = ConfigDict(extra='forbid')
    content_type: MediaType | None = None
    content_length: Counter | None = None


class RequestEvent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    timestamp: AwareDatetime
    request_id: str = Field(pattern=r'^[a-zA-Z0-9_.:-]{1,80}$')
    method: Literal['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'OTHER']
    route: str = Field(pattern=r'^(?:/[^?#\r\n]{0,199}|<unmatched>)$')
    status: int = Field(ge=100, le=599)
    duration_ms: float = Field(ge=0, allow_inf_nan=False)
    request_bytes: Counter
    response_bytes: Counter
    source_ip: IPvAnyAddress | None = None
    url_scheme: Literal['http', 'https'] | None = None
    url_host: str | None = Field(None, pattern=r'^[A-Za-z0-9.:\[\]-]{1,253}$')
    request_headers: HeaderMetadata | None = None
    response_headers: HeaderMetadata | None = None
    request_body_fields: list[BodyField] = Field(default_factory=list, max_length=11)
    response_body_fields: list[BodyField] = Field(default_factory=list, max_length=11)
    security_event: Literal['login_success', 'login_failure', 'access_denied', 'permission_changed'] | None = None


class ServiceBatch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    batch_id: UUID
    service: Source
    interval_start: AwareDatetime
    interval_end: AwareDatetime
    status_classes: dict[Literal['1xx', '2xx', '3xx', '4xx', '5xx'], Counter] = Field(max_length=5)
    status_codes: dict[Annotated[str, StringConstraints(pattern=r'^[1-5][0-9]{2}$')], Counter] = Field(max_length=500)
    latency_buckets: list[Counter] = Field(min_length=11, max_length=11)
    omitted_details: Counter
    invalid_lines: Counter
    events: list[RequestEvent] = Field(max_length=300)


def store_batch(database, batch, digest, received):
    collection = database[COLLECTION]
    identity = f'{batch.service}:{batch.batch_id}'
    document = batch.model_dump(mode='json', exclude_none=True)
    document.update(interval_start=batch.interval_start, interval_end=batch.interval_end,
                    received_at=received, digest=digest)
    try:
        result = collection.update_one({'_id': identity}, {'$setOnInsert': document}, upsert=True)
        duplicate = result.upserted_id is None
    except DuplicateKeyError:
        duplicate = True
    if duplicate:
        existing = collection.find_one({'_id': identity}, {'digest': 1, 'received_at': 1})
        if existing is None or existing.get('digest') != digest:
            raise HTTPException(409, 'Batch ID already used for different data')
        received = existing['received_at']
    if batch.events:
        operations = []
        for position, event in enumerate(batch.events):
            row = event.model_dump(mode='json', exclude_none=True)
            row.update(timestamp=event.timestamp, received_at=received, service=batch.service,
                       batch_id=str(batch.batch_id))
            operations.append(UpdateOne(
                {'_id': f'{identity}:{position}'}, {'$setOnInsert': row}, upsert=True))
        database[RECORDS].bulk_write(operations, ordered=False)
    return {'batch_id': batch.batch_id, 'duplicate': duplicate}


@router.post(INGEST_PATH, status_code=202, summary='دریافت دستهٔ امضاشدهٔ لاگ وب‌سرویس')
async def receive_batch(request: Request, database: DB):
    service = request.headers.get('x-siem-service', '')
    secret = request.app.state.settings.web_collector_keys.get(service)
    if secret is None:
        raise HTTPException(401, 'Unknown collector')
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BODY:
            raise HTTPException(413, 'Batch exceeds maximum size')
        body.extend(chunk)
    signature = hmac.digest(secret.get_secret_value().encode(), body, 'sha256').hex()
    supplied = request.headers.get('x-siem-signature', '')
    if not hmac.compare_digest(signature.encode(), supplied.encode()):
        raise HTTPException(401, 'Invalid collector signature')
    try:
        batch = ServiceBatch.model_validate_json(bytes(body))
    except ValidationError as exc:
        raise HTTPException(422, 'Invalid web-service batch') from exc
    now = datetime.now(timezone.utc)
    if (batch.service != service or batch.interval_end - batch.interval_start != timedelta(minutes=1)
            or not now - timedelta(seconds=RETENTION) <= batch.interval_end <= now + timedelta(minutes=5)):
        raise HTTPException(422, 'Invalid service or batch interval')
    total = sum(batch.status_codes.values())
    classes = {f'{i}xx': sum(count for code, count in batch.status_codes.items() if code[0] == str(i))
               for i in range(1, 6)}
    if (any(batch.status_classes.get(key, 0) != count for key, count in classes.items())
            or sum(batch.latency_buckets) != total or len(batch.events) + batch.omitted_details != total):
        raise HTTPException(422, 'Batch counters do not agree')
    return await run_in_threadpool(store_batch, database, batch, sha256(body).hexdigest(), now)


@router.get('/api/v1/web-services/batches', summary='آخرین دسته‌های شمارنده، هیستوگرام و لاگ وب‌سرویس')
def recent_batches(database: DB, service: Source | None = None, limit: int = Query(10, ge=1, le=30)):
    query = {'service': service} if service else {}
    items = list(database[COLLECTION].find(query, {'digest': 0}).sort(
        [('interval_end', -1), ('_id', -1)]).limit(limit))
    return {'histogram_upper_bounds_ms': HISTOGRAM_BOUNDS_MS, 'items': items}
