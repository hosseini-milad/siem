from contextlib import asynccontextmanager
from threading import Lock
from datetime import datetime, timezone
import logging

from app.api import access, alerts, dashboard, detections, explorer, incidents, ingestion, search, system, tasks, web_services

from app.api.machine_learning import router as machine_learning_router
from app.services.machine_learning import ModelManager
from app.api.standardization import router as standardization_router
from app.api.datasets import router as datasets_router
from app.api.system_log_datasets import router as system_log_datasets_router
from app.api.system_log_ml import router as system_log_ml_router
from app.api.normalization import router as normalization_router

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse, RedirectResponse
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from starlette.concurrency import run_in_threadpool

from app.api.logs import http_ingestion_router, router
from app.core.config import Settings
from app.models.log import COLLECTION, RETENTION_SECONDS
from app.services.access import initialize_access
from app.services.agent_ingestion import (AGENT_LOGS, PAYLOADS, SYSTEM_METRICS, SYSTEMS,
                                          SYSTEM_CHANGES, bootstrap_systems)
from app.services.explorer import DATASET_IP_COLUMNS, DATASET_ORDER, LOG_ORDER
from app.services.raw_logs import listen_for_raw_logs
from app.services.web_access import WebAccessLog, access_log_handler
from app.services.system_log_ml import AGENT_LOG_LABELS, SystemLogModelManager


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()
    access_handler = access_log_handler(config.web_access_log_path) if config.web_access_log_path else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.ml = ModelManager(config.ml_model_dir, config.ml_threads)
        app.state.system_log_ml = SystemLogModelManager()
        client = MongoClient(config.mongodb_uri, tz_aware=True, serverSelectionTimeoutMS=config.mongodb_server_selection_timeout_ms,
                             connectTimeoutMS=config.mongodb_connect_timeout_ms,
                             socketTimeoutMS=config.mongodb_socket_timeout_ms)
        app.state.database = client[config.mongodb_database]
        try:
            def initialize():
                client.admin.command("ping")
                batches = app.state.database[web_services.COLLECTION]
                batches.create_index('received_at', expireAfterSeconds=web_services.RETENTION)
                batches.create_index([('interval_end', -1), ('_id', -1)])
                batches.create_index([('service', 1), ('interval_end', -1), ('_id', -1)])
                web_records = app.state.database[web_services.RECORDS]
                web_records.create_index('received_at', expireAfterSeconds=web_services.RETENTION)
                web_records.create_index(LOG_ORDER)
                web_records.create_index([('service', 1), *LOG_ORDER])
                web_records.create_index([('status', 1), *LOG_ORDER])
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
                app.state.database.system_log_dataset_imports.update_many(
                    {"status": "running"}, {"$set": {"status": "interrupted",
                     "finished_at": datetime.now(timezone.utc)}})
                app.state.database.system_log_normalization_runs.update_many(
                    {"status": "running"}, {"$set": {"status": "interrupted",
                     "finished_at": datetime.now(timezone.utc)}})
                app.state.database.system_log_training_runs.update_many(
                    {"status": "running"}, {"$set": {"status": "interrupted",
                     "finished_at": datetime.now(timezone.utc)}})
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
                app.state.database.system_log_dataset_records.create_index(
                    [("_import.file", 1), ("_import.record_number", 1)])
                app.state.database.system_log_dataset_imports.create_index([("created_at", -1)])
                app.state.database.system_log_dataset_normal.create_index("original_id", unique=True)
                app.state.database.system_log_dataset_normal.create_index(
                    [("normalization_version", 1), ("Label", 1)])
                app.state.database.system_log_models.create_index([("created_at", -1)])
                app.state.database.system_log_models.create_index(
                    "active", unique=True, partialFilterExpression={"active": True})
                app.state.database.system_log_normalization_runs.create_index([("created_at", -1)])
                app.state.database.system_log_training_runs.create_index([("created_at", -1)])
                for columns in DATASET_IP_COLUMNS.values():
                    for column in columns:
                        dataset.create_index([(column, 1), *DATASET_ORDER],
                                             partialFilterExpression={column: {'$exists': True}})
                collection = app.state.database[COLLECTION]
                collection.create_index(LOG_ORDER)
                collection.create_index([("source", 1), ("timestamp", -1)])
                collection.create_index([("level", 1), ("timestamp", -1)])
                collection.create_index("received_at", expireAfterSeconds=RETENTION_SECONDS)
                app.state.database[PAYLOADS].create_index("received_at", expireAfterSeconds=RETENTION_SECONDS)
                app.state.database[PAYLOADS].create_index([("agent_id", 1), ("timestamp", -1)])
                app.state.database[AGENT_LOGS].create_index("received_at", expireAfterSeconds=RETENTION_SECONDS)
                labeled_logs = app.state.database[AGENT_LOG_LABELS]
                labeled_logs.create_index("received_at", expireAfterSeconds=RETENTION_SECONDS)
                labeled_logs.create_index(LOG_ORDER)
                labeled_logs.create_index([("agent_id", 1), *LOG_ORDER])
                labeled_logs.create_index([("predicted_label", 1), *LOG_ORDER])
                app.state.database[AGENT_LOGS].create_index([("system_id", 1), ("timestamp", -1)])
                app.state.database[AGENT_LOGS].create_index([("event_id", 1), ("timestamp", -1)])
                app.state.database[SYSTEM_METRICS].create_index("received_at", expireAfterSeconds=RETENTION_SECONDS)
                app.state.database[SYSTEM_METRICS].create_index([("system_id", 1), ("received_at", -1)])
                app.state.database[SYSTEMS].create_index("mac", unique=True)
                app.state.database[SYSTEMS].create_index([("agent_id", 1), ("last_seen", -1)])
                app.state.database[SYSTEM_CHANGES].create_index([("system_id", 1), ("changed_at", -1)])
                bootstrap_systems(app.state.database)
                try:
                    app.state.system_log_ml.load(app.state.database)
                except Exception:
                    logging.getLogger('uvicorn.error.siem.system_log_ml').exception(
                        'Active system-log model could not be loaded; retrain before prediction')
                app.state.database.siem_alerts.create_index([("status", 1), ("severity", 1), ("created_at", -1)])
                app.state.database.siem_alerts.create_index([("created_at", -1), ("_id", -1)])
                app.state.database.siem_alerts.create_index([("domain", 1), ("created_at", -1), ("_id", -1)])
                app.state.database.siem_incidents.create_index([("status", 1), ("created_at", -1)])
                app.state.database.siem_rules.create_index("enabled")
            await run_in_threadpool(initialize)
            if config.raw_log_port:
                async with listen_for_raw_logs(app.state.database, config.raw_log_host, config.raw_log_port):
                    yield
            else:
                yield
        finally:
            client.close()
            if access_handler is not None:
                access_handler.close()

    app = FastAPI(title="SIEM API", version="0.1.0", lifespan=lifespan,
                  description="SIEM هوشمند: رویدادها، هشدارها، قواعد، رخدادها، جست‌وجوی MongoDB و مدل‌های LightGBM/CatBoost. با احراز هویت و کنترل دسترسی.",
                  dependencies=[Depends(access.authorize)],
                  openapi_tags=[*system.OPENAPI_TAGS, {"name": "Access"}, {"name": "Tasks"}],
                  swagger_ui_parameters={"displayRequestDuration": True, "docExpansion": "none"},
                  responses={503: {"description": "MongoDB operation unavailable; batch writes may be partial"}})
    if access_handler is not None:
        app.add_middleware(WebAccessLog, handler=access_handler)
    app.state.settings = config
    app.state.import_lock = Lock()
    app.include_router(access.router)
    app.include_router(router)
    app.include_router(http_ingestion_router)
    app.include_router(datasets_router)
    app.include_router(system_log_datasets_router)
    app.include_router(system_log_ml_router)
    app.include_router(normalization_router)
    app.include_router(standardization_router)
    app.include_router(machine_learning_router)
    for module in (ingestion, search, explorer, dashboard, detections, alerts, incidents, system, tasks, web_services):
        app.include_router(module.router)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        if request.url.path.startswith(('/api/v1/auth/', '/api/v1/users', '/api/v1/device-health')):
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
