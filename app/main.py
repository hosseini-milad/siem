from contextlib import asynccontextmanager
from threading import Lock
from datetime import datetime, timezone
import logging

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
                collection = app.state.database[COLLECTION]
                collection.create_index([("timestamp", -1), ("_id", -1)])
                collection.create_index([("source", 1), ("timestamp", -1)])
                collection.create_index([("level", 1), ("timestamp", -1)])
            await run_in_threadpool(initialize)
            yield
        finally:
            client.close()

    app = FastAPI(title="SIEM API", version="0.1.0", lifespan=lifespan,
                  description="فاز اول: دریافت و ذخیره لاگ در MongoDB. بدون احراز هویت و هوش مصنوعی.",
                  swagger_ui_parameters={"displayRequestDuration": True},
                  responses={503: {"description": "MongoDB unavailable; batch writes may be partial"}})
    app.state.settings = config
    app.state.import_lock = Lock()
    app.include_router(router)
    app.include_router(datasets_router)
    app.include_router(normalization_router)

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
