import logging
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, Field
from pymongo.errors import ExecutionTimeout, PyMongoError

from app.db.session import DB
from app.schemas.log import LogLevel
from app.services.explorer import list_records, list_system_records

logger = logging.getLogger('uvicorn.error.siem.explorer')
router = APIRouter(prefix='/api/v1/explorer', tags=['Search'])


class ExplorerFilters(BaseModel):
    kind: Literal['data', 'logs'] = 'data'
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    q: str = Field('', max_length=1024, pattern=r'^[^\x00]*$')
    source_ip: str | None = Field(None, max_length=45)
    destination_ip: str | None = Field(None, max_length=45)
    source_port: int | None = Field(None, ge=0, le=65535)
    destination_port: int | None = Field(None, ge=0, le=65535)
    protocol: Literal['TCP', 'UDP', 'ICMP'] | None = None
    level: LogLevel | None = None
    risk: Literal['benign', 'low', 'medium', 'high', 'critical', 'attack', 'unscored'] | None = None
    limit: int = Field(15, ge=1, le=100)
    offset: int = Field(0, ge=0)


@router.get('/records', summary='کاوش داده‌های خام و لاگ‌ها با فیلتر شبکه و اطلاعات نرمال‌شده')
def records(database: DB, filters: Annotated[ExplorerFilters, Query()]):
    if filters.start and filters.end and filters.start >= filters.end:
        raise HTTPException(422, 'start must be earlier than end')
    try:
        return list_records(database, filters)
    except ExecutionTimeout as exc:
        logger.warning('MongoDB explorer query timed out (kind=%s)', filters.kind)
        raise HTTPException(503, 'Explorer query timed out. Try a smaller date range or more specific filters.') from exc
    except PyMongoError as exc:
        logger.error('MongoDB explorer query failed (kind=%s, error=%s, code=%s)',
                     filters.kind, type(exc).__name__, getattr(exc, 'code', None))
        raise


@router.get('/system-records', summary='کاوش لاگ‌های سیستم برچسب‌خورده')
def system_records(
    database: DB, start: AwareDatetime | None = None, end: AwareDatetime | None = None,
    q: str = Query('', max_length=255), label: str | None = Query(None, max_length=64),
    limit: int = Query(15, ge=1, le=100), offset: int = Query(0, ge=0),
):
    if start and end and start >= end:
        raise HTTPException(422, 'start must be earlier than end')
    try:
        return list_system_records(database, start, end, q.strip(), label, limit, offset)
    except ExecutionTimeout as exc:
        raise HTTPException(503, 'Explorer query timed out. Try a smaller date range.') from exc
