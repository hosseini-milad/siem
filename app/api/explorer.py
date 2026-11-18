from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, Field

from app.db.session import DB
from app.schemas.log import LogLevel
from app.services.explorer import list_records

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
    risk: Literal['low', 'medium', 'high', 'critical', 'unscored'] | None = None
    limit: int = Field(15, ge=1, le=100)
    offset: int = Field(0, ge=0)


@router.get('/records', summary='کاوش داده‌های خام و لاگ‌ها با فیلتر شبکه و اطلاعات نرمال‌شده')
def records(database: DB, filters: Annotated[ExplorerFilters, Query()]):
    if filters.start and filters.end and filters.start >= filters.end:
        raise HTTPException(422, 'start must be earlier than end')
    return list_records(database, filters)
