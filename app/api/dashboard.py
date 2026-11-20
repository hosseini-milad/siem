from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse

from app.api.search import EventFilters
from app.db.session import DB
from app.services import dashboard, search

router = APIRouter()


@router.get('/dashboard', include_in_schema=False)
def dashboard_page():
    return FileResponse(Path(__file__).parents[1] / 'web' / 'dashboard.html', media_type='text/html')


@router.get('/api/v1/overview', tags=['Overview'], summary='نمای کلی وضعیت عملیاتی SIEM')
def overview(database: DB, hours: int = Query(24, ge=1, le=720)):
    return dashboard.overview(database, hours)


@router.get('/api/v1/overview/operations', tags=['Overview'], summary='نمای عملیات هشدار و حجم لاگ در سه مسیر')
def operations(database: DB, hours: int = Query(24, ge=1, le=720)):
    return dashboard.operational_overview(database, hours)


@router.get('/api/v1/dashboard/charts', tags=['Overview'], summary='روند زمانی، سطح و منابع رویدادها')
def charts(database: DB, query: EventFilters, interval: Literal['hour', 'day'] = 'hour'):
    return {'interval': interval, **search.statistics(database, query, interval)}
