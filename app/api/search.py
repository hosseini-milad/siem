from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime

from app.db.session import DB
from app.schemas.log import LogLevel
from app.services import search

router = APIRouter(prefix='/api/v1/search', tags=['Search'])


def event_filters(
    q: str = Query('', max_length=1024),
    source: str | None = Query(None, max_length=255),
    level: LogLevel | None = None,
    start: AwareDatetime | None = None,
    end: AwareDatetime | None = None,
):
    until = end or datetime.now(timezone.utc)
    since = start or until - timedelta(hours=24)
    if since > until:
        raise HTTPException(422, 'start must be before or equal to end')
    if until - since > timedelta(days=30):
        raise HTTPException(422, 'The search window must not exceed 30 days')
    return search.event_filter(source=source, level=level, start=since, end=until, q=q)


EventFilters = Annotated[dict, Depends(event_filters)]


@router.get('/events', summary='جست‌وجوی متن، فیلتر و صفحه‌بندی رویدادهای MongoDB')
def events(
    database: DB,
    query: EventFilters,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=10000),
):
    return {**search.page(database, query, limit, offset, timeout_ms=search.QUERY_TIMEOUT_MS),
            'engine': 'mongodb'}
