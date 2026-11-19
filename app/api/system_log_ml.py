from datetime import datetime, timezone
from uuid import UUID, uuid4

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.db.session import DB
from app.services.system_log_ml import (MODELS, NORMAL, NORMAL_RUNS, NORMALIZATION_VERSION,
                                        TRAINING_RUNS, class_counts, normalize_dataset,
                                        train_models)

router = APIRouter(prefix="/api/v1/system-log-ml", tags=["Machine Learning"])


class TrainingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_records: int = Field(default=200000, ge=100, le=1000000)
    rounds: int = Field(default=300, ge=10, le=2000)
    random_seed: int = Field(default=42, ge=0, le=2147483647)


class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    records: list[dict] = Field(min_length=1, max_length=500)


def acquire(request):
    if not request.app.state.import_lock.acquire(blocking=False):
        raise HTTPException(409, "Another import, normalization or training operation is running")


@router.post("/normalization/runs", status_code=202,
             summary="نرمال‌سازی دیتاست برچسب‌دار Sysmon")
def start_normalization(request: Request, tasks: BackgroundTasks, database: DB):
    acquire(request)
    job_id = str(uuid4())
    try:
        database[NORMAL_RUNS].insert_one({
            "_id": job_id, "status": "running", "phase": "queued", "processed": 0,
            "skipped": 0, "failed": 0, "created_at": datetime.now(timezone.utc),
            "normalization_version": NORMALIZATION_VERSION,
        })
    except Exception:
        request.app.state.import_lock.release()
        raise

    def run():
        try:
            normalize_dataset(database, job_id)
        finally:
            request.app.state.import_lock.release()

    tasks.add_task(run)
    return {"id": job_id, "status": "running"}


@router.get("/normalization/runs/{run_id}", summary="وضعیت نرمال‌سازی Sysmon")
def normalization_status(run_id: UUID, database: DB):
    row = database[NORMAL_RUNS].find_one({"_id": str(run_id)})
    if row is None:
        raise HTTPException(404, "System-log normalization run not found")
    return row


@router.get("/normalization/records", summary="نمونه داده‌های نرمال‌شده Sysmon")
def normalized_records(database: DB, limit: int = Query(20, ge=1, le=100),
                       offset: int = Query(0, ge=0, le=100000)):
    return {"items": list(database[NORMAL].find().sort("_id", 1).skip(offset).limit(limit)),
            "total": database[NORMAL].count_documents({}), "limit": limit, "offset": offset}


@router.get("/labels", summary="تعداد رکوردهای نرمال‌شده برای هر Label")
def labels(database: DB):
    return {"normalization_version": NORMALIZATION_VERSION, "counts": class_counts(database)}


@router.post("/training/runs", status_code=202,
             summary="آموزش و ارزیابی مدل Label لاگ سیستم")
def start_training(body: TrainingRequest, request: Request, tasks: BackgroundTasks, database: DB):
    acquire(request)
    job_id = str(uuid4())
    manager = request.app.state.system_log_ml
    threads = request.app.state.settings.ml_threads
    try:
        database[TRAINING_RUNS].insert_one({
            "_id": job_id, "status": "running", "phase": "queued",
            "created_at": datetime.now(timezone.utc), "max_records": body.max_records,
            "rounds": body.rounds, "random_seed": body.random_seed,
        })
    except Exception:
        request.app.state.import_lock.release()
        raise

    def run():
        try:
            train_models(database, job_id, body.max_records, body.rounds, body.random_seed,
                         threads, manager)
        finally:
            request.app.state.import_lock.release()

    tasks.add_task(run)
    return {"id": job_id, "status": "running"}


@router.get("/training/runs/{run_id}", summary="وضعیت آموزش و ارزیابی مدل Sysmon")
def training_status(run_id: UUID, database: DB):
    row = database[TRAINING_RUNS].find_one({"_id": str(run_id)})
    if row is None:
        raise HTTPException(404, "System-log training run not found")
    return row


def model_view(row):
    result = dict(row)
    if isinstance(result.get("artifact_file_id"), ObjectId):
        result["artifact_file_id"] = str(result["artifact_file_id"])
    return result


@router.get("/models/current", summary="مدل فعال، وزن ویژگی‌ها و ارزیابی Sysmon")
def current_model(database: DB):
    row = database[MODELS].find_one({"active": True}, sort=[("created_at", -1)])
    if row is None:
        raise HTTPException(404, "No accepted system-log model is active")
    return model_view(row)


@router.get("/models", summary="تاریخچه مدل‌های Sysmon")
def models(database: DB, limit: int = Query(20, ge=1, le=100)):
    projection = {"feature_weights": 0}
    rows = [model_view(row) for row in database[MODELS].find({}, projection).sort("created_at", -1).limit(limit)]
    return {"items": rows, "total": database[MODELS].count_documents({}), "limit": limit}


@router.post("/predict", summary="تشخیص Label برای لاگ‌های خام Sysmon")
def predict(body: PredictRequest, request: Request):
    try:
        predictor = request.app.state.system_log_ml.require()
        return {"model_id": predictor.model_id, "items": predictor.predict(body.records)}
    except LookupError as exc:
        raise HTTPException(503, str(exc)) from exc
    except (ValueError, TypeError, OverflowError) as exc:
        raise HTTPException(422, str(exc)) from exc
