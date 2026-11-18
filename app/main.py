from contextlib import asynccontextmanager
from threading import Lock
from datetime import datetime, timezone
import logging

from app.api import access, alerts, dashboard, detections, explorer, incidents, ingestion, search, system

from app.api.machine_learning import router as machine_learning_router
from app.services.machine_learning import ModelManager
from app.api.standardization import router as standardization_router
from app.api.datasets import router as datasets_router
from app.api.normalization import router as normalization_router

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse, RedirectResponse
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from starlette.concurrency import run_in_threadpool

from app.api.logs import router
from app.core.config import Settings
from app.models.log import COLLECTION
from app.services.access import initialize_access
from app.services.explorer import DATASET_IP_COLUMNS, DATASET_ORDER, LOG_ORDER


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.ml = ModelManager(config.ml_model_dir, config.ml_threads)
        client = MongoClient(config.mongodb_uri, tz_aware=True, serverSelectionTimeoutMS=config.mongodb_server_selection_timeout_ms,
                             connectTimeoutMS=config.mongodb_connect_timeout_ms,
                             socketTimeoutMS=config.mongodb_socket_timeout_ms)
        app.state.database = client[config.mongodb_database]
        try:
            def initialize():
                client.admin.command("ping")
                if config.auth_required:
                    initialize_access(app.state.database)
                interrupted = app.state.database.normalization_runs.update_many(
                    {"status": "running"}, {"$set": {"status": "interrupted",
                     "interruption_reason": "Server started again before this run finished (restart, reload, or another worker)",
                     "interrupted_at": datetime.now(timezone.utc)}})
                if interrupted.modified_count:
                    logging.getLogger('uvicorn.error.siem.normalization').warning(
                        'Startup marked %s previous normalization runs interrupted; use one worker and no reload',
                        interrupted.modified_count)
                app.state.database.dataset_imports.update_many({"status": "running"}, {"$set": {"status": "interrupted"}})
                app.state.database.standardization_runs.update_many(
                    {"status": "running"}, {"$set": {"status": "interrupted",
                     "interruption_reason": "Server restarted; rerun standardization to rebuild blocks",
                     "interrupted_at": datetime.now(timezone.utc)}})
                app.state.database.ml_training_runs.update_many(
                    {"status": "running"}, {"$set": {"status": "interrupted",
                     "interruption_reason": "Server restarted during training",
                     "interrupted_at": datetime.now(timezone.utc)}})
                dataset = app.state.database.dataset_records
                dataset.create_index(DATASET_ORDER)
                for columns in DATASET_IP_COLUMNS.values():
                    for column in columns:
                        dataset.create_index([(column, 1), *DATASET_ORDER],
                                             partialFilterExpression={column: {'$exists': True}})
                collection = app.state.database[COLLECTION]
                collection.create_index(LOG_ORDER)
                collection.create_index([("source", 1), ("timestamp", -1)])
                collection.create_index([("level", 1), ("timestamp", -1)])
                app.state.database.siem_alerts.create_index([("status", 1), ("severity", 1), ("created_at", -1)])
                app.state.database.siem_incidents.create_index([("status", 1), ("created_at", -1)])
                app.state.database.siem_rules.create_index("enabled")
            await run_in_threadpool(initialize)
            yield
        finally:
            client.close()

    app = FastAPI(title="SIEM API", version="0.1.0", lifespan=lifespan,
                  description="SIEM هوشمند: رویدادها، هشدارها، قواعد، رخدادها، جست‌وجوی MongoDB و مدل‌های LightGBM/CatBoost. با احراز هویت و کنترل دسترسی.",
                  dependencies=[Depends(access.authorize)],
                  openapi_tags=[*system.OPENAPI_TAGS, {"name": "Access"}],
                  swagger_ui_parameters={"displayRequestDuration": True, "docExpansion": "none"},
                  responses={503: {"description": "MongoDB operation unavailable; batch writes may be partial"}})
    app.state.settings = config
    app.state.import_lock = Lock()
    app.include_router(access.router)
    app.include_router(router)
    app.include_router(datasets_router)
    app.include_router(normalization_router)
    app.include_router(standardization_router)
    app.include_router(machine_learning_router)
    for module in (ingestion, search, explorer, dashboard, detections, alerts, incidents, system):
        app.include_router(module.router)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        if request.url.path.startswith(('/api/v1/auth/', '/api/v1/users')):
            return JSONResponse(status_code=422, content={"detail": "مقادیر فرم معتبر نیستند."})
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(PyMongoError)
    async def database_error(request: Request, exc: PyMongoError):
        return JSONResponse(status_code=503, content={"detail": "Database unavailable; a batch write may be partial. Check stored records before retrying."})

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/docs")

    return app


app = create_app()
