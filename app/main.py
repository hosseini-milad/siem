from contextlib import asynccontextmanager
from threading import Lock
from datetime import datetime, timezone
import logging
import httpx

from app.api.siem import router as siem_router, TAGS
from app.services.elk import Elk, IntegrationUnavailable

from app.api.machine_learning import router as machine_learning_router
from app.services.machine_learning import ModelManager
from app.api.standardization import router as standardization_router
from app.api.datasets import router as datasets_router
from app.api.normalization import router as normalization_router

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from starlette.concurrency import run_in_threadpool

from app.api.logs import router
from app.core.config import Settings
from app.models.log import COLLECTION


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.ml = ModelManager(config.ml_model_dir, config.ml_threads)
        elk_client = httpx.Client(timeout=config.elk_timeout_seconds, trust_env=False)
        app.state.elk = Elk(config, elk_client)
        client = MongoClient(config.mongodb_uri, tz_aware=True, serverSelectionTimeoutMS=config.mongodb_server_selection_timeout_ms,
                             connectTimeoutMS=config.mongodb_connect_timeout_ms,
                             socketTimeoutMS=config.mongodb_socket_timeout_ms)
        app.state.database = client[config.mongodb_database]
        try:
            def initialize():
                client.admin.command("ping")
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
                collection = app.state.database[COLLECTION]
                collection.create_index([("timestamp", -1), ("_id", -1)])
                collection.create_index([("source", 1), ("timestamp", -1)])
                collection.create_index([("level", 1), ("timestamp", -1)])
                collection.create_index([("_search_index", 1), ("received_at", 1), ("_id", 1)])
                app.state.database.siem_alerts.create_index([("status", 1), ("severity", 1), ("created_at", -1)])
                app.state.database.siem_incidents.create_index([("status", 1), ("created_at", -1)])
                app.state.database.siem_rules.create_index("enabled")
            await run_in_threadpool(initialize)
            yield
        finally:
            elk_client.close()
            client.close()

    app = FastAPI(title="SIEM API", version="0.1.0", lifespan=lifespan,
                  description="SIEM هوشمند: رویدادها، هشدارها، قواعد، رخدادها، ELK و مدل‌های LightGBM/CatBoost. بدون احراز هویت؛ اجنت‌ها خارج از این مرحله‌اند.",
                  openapi_tags=[{"name": name, "description": description} for name, description in TAGS],
                  swagger_ui_parameters={"displayRequestDuration": True, "docExpansion": "none"},
                  responses={503: {"description": "Storage or ELK service unavailable; batch writes may be partial"}})
    app.state.settings = config
    app.state.import_lock = Lock()
    app.state.search_sync_lock = Lock()
    app.include_router(router)
    app.include_router(datasets_router)
    app.include_router(normalization_router)
    app.include_router(standardization_router)
    app.include_router(machine_learning_router)
    app.include_router(siem_router)

    @app.exception_handler(IntegrationUnavailable)
    async def integration_error(request: Request, exc: IntegrationUnavailable):
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.exception_handler(PyMongoError)
    async def database_error(request: Request, exc: PyMongoError):
        return JSONResponse(status_code=503, content={"detail": "Database unavailable; a batch write may be partial. Check stored records before retrying."})

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/docs")

    @app.get("/api/v1/health", tags=["Health"], summary="بررسی اتصال دیتابیس")
    def health(request: Request):
        request.app.state.database.command("ping")
        return {"status": "ok", "database": "mongodb"}

    return app


app = create_app()
