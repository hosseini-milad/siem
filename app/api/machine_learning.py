from datetime import datetime, timezone
from time import perf_counter
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, Query
import orjson
from pydantic import BaseModel, Field, ConfigDict
from pymongo import UpdateOne, timeout
from pymongo.errors import PyMongoError

from app.services.ml_diagnostics import data_diagnostics

from app.api.logs import DB
from app.services.machine_learning import EXCLUDED_MODEL_FEATURES, NON_FEATURE_FIELDS, training_job
from app.services.normalization import EXCLUDED
from app.services.standardization import BLOCK_SIZE

router = APIRouter(prefix='/api/v1/ml', tags=['Machine Learning'])


class TrainingRequest(BaseModel):
    max_records: int = Field(default=300000, ge=50000, le=1000000, multiple_of=10000)
    threshold: float = Field(default=0.5, gt=0, lt=1)
    rounds: int = Field(default=500, ge=10, le=2000)
    random_seed: int = Field(default=42, ge=0, le=2147483647)


class PredictRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    records: list[dict] = Field(min_length=1, max_length=BLOCK_SIZE)
    input_format: Literal['standard', 'raw'] = 'standard'
    persist: bool = False


class MatrixRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    matrix: list[list[float]] = Field(min_length=1, max_length=BLOCK_SIZE)


def active(request):
    try:
        return request.app.state.ml.require()
    except LookupError as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get('/model', summary='مدل جاری، ترتیب ویژگی‌ها و مقایسهٔ LightGBM و CatBoost')
def model(request: Request):
    manager = request.app.state.ml
    with manager.state_lock:
        predictor = manager.active
        if predictor is None:
            raise HTTPException(503, 'No trained model is active')
        metadata = {key: value for key, value in predictor.artifact.items() if key not in {'booster', 'catboost'}}
        try:
            manager.require()
            metadata['serving_eligible'] = True
        except LookupError as exc:
            metadata['serving_eligible'] = False
            metadata['serving_block_reason'] = str(exc)
    schema = metadata.get('normalization_schema') or []
    metadata['input_requirements'] = {
        'min_rows': 1,
        'max_rows': BLOCK_SIZE,
        'value_range': [0, 1],
        'matrix': {'columns': len(predictor.names), 'dtype': 'float32'},
        'standard': {'ignored_fields': sorted(NON_FEATURE_FIELDS | EXCLUDED_MODEL_FEATURES)},
        'raw': {
            'available': bool(schema and metadata.get('behavior_bounds')),
            'fields': [{'name': stat['field'], 'kind': stat['kind']} for stat in schema],
            'ignored_fields': sorted(EXCLUDED | {'Label'}),
        },
    }
    return metadata


@router.post('/training/runs', status_code=202, summary='آموزش CPU از بلوک‌های کامل متناظر با standard_records')
def start_training(body: TrainingRequest, request: Request, tasks: BackgroundTasks, database: DB):
    manager = request.app.state.ml
    if not manager.training_lock.acquire(blocking=False):
        raise HTTPException(409, 'Training is already running')
    if not request.app.state.import_lock.acquire(blocking=False):
        manager.training_lock.release()
        raise HTTPException(409, 'Dataset import, normalization or standardization is running')
    job_id = 'current'
    try:
        manager.clear()
        database.ml_training_runs.delete_many({})
        database.ml_predictions.delete_many({})
        database.ml_training_runs.insert_one({'_id': job_id, 'status': 'running', 'phase': 'queued',
                                              'created_at': datetime.now(timezone.utc)})
    except Exception:
        request.app.state.import_lock.release()
        manager.training_lock.release()
        raise

    def run():
        try:
            training_job(database, manager, job_id, body.max_records, body.threshold, body.rounds, body.random_seed)
        finally:
            request.app.state.import_lock.release()
            manager.training_lock.release()
    tasks.add_task(run)
    return {'id': job_id, 'status': 'running'}


@router.get('/training/runs/{run_id}')
def training_status(run_id: str, database: DB):
    if run_id != 'current':
        raise HTTPException(404, 'Only the current training report is retained')
    row = database.ml_training_runs.find_one({'_id': 'current'})
    if row is None:
        raise HTTPException(404, 'Training run not found')
    return row


@router.post('/predict', summary='پیش‌بینی اینلاین رکورد استاندارد یا خام بدون Label؛ حداکثر ۱۰۰۰۰ رکورد')
def predict(body: PredictRequest, request: Request):
    started = perf_counter()
    predictor = active(request)
    if body.persist:
        ids = [row.get('original_id', row.get('_id')) for row in body.records]
        if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids):
            raise HTTPException(422, 'Persistence requires distinct nonempty string original_id or _id values')
    try:
        response = predictor.predict(records=body.records, raw=body.input_format == 'raw')
    except (ValueError, TypeError, OverflowError) as exc:
        raise HTTPException(422, str(exc)) from exc
    write_start = perf_counter()
    with request.app.state.ml.state_lock:
        if request.app.state.ml.active is not predictor:
            raise HTTPException(503, 'Model was reset during prediction; retry after training completes')
        if body.persist:
            now = datetime.now(timezone.utc)
            request.app.state.database.ml_predictions.bulk_write([
                UpdateOne({'_id': item['original_id']}, {'$set': {
                    **item, 'predicted_at': now}}, upsert=True)
                for item in response['items']])
    response['timing_ms']['database_write'] = (perf_counter() - write_start) * 1000 if body.persist else 0.0
    response['timing_ms']['handler_total'] = (perf_counter() - started) * 1000
    return Response(orjson.dumps(response), media_type='application/json')


@router.post('/predict-matrix', summary='مسیر سریع ماتریس float32 با ترتیب ویژگی‌های مدل؛ بدون دیتابیس')
def predict_matrix(body: MatrixRequest, request: Request):
    predictor = active(request)
    try:
        result = predictor.predict(matrix=body.matrix)
        with request.app.state.ml.state_lock:
            if request.app.state.ml.active is not predictor:
                raise HTTPException(503, 'Model was reset during prediction; retry after training completes')
            return Response(orjson.dumps(result), media_type='application/json')
    except (ValueError, TypeError, OverflowError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get('/data-diagnostics', summary='آمار فقط‌خواندنی کلاس‌ها و ویژگی‌های استاندارد؛ بدون نیاز به mongosh')
def inspect_data(database: DB, sample_size: int = Query(20000, ge=1, le=50000),
                 full_label_counts: bool = Query(False),
                 max_time_ms: int = Query(300000, ge=1000, le=900000)):
    try:
        # CSOT overrides the client's short socketTimeoutMS for this request only.
        # Allow both aggregations plus transport/metadata overhead when full counts are requested.
        budget_seconds = (max_time_ms * (2 if full_label_counts else 1) + 30000) / 1000
        with timeout(budget_seconds):
            return data_diagnostics(database, sample_size, full_label_counts, max_time_ms)
    except PyMongoError as exc:
        if not exc.timeout:
            raise
        raise HTTPException(504, f'Diagnostics timed out with max_time_ms={max_time_ms} per aggregation. '
                            'Increase max_time_ms up to 900000, reduce sample_size, or disable full_label_counts. '
                            'The diagnostics request has its own MongoDB timeout budget.') from exc
