from uuid import UUID

from fastapi import APIRouter, HTTPException

from app.db.session import DB
from app.schemas.siem import IngestionBatch
from app.services import ingestion, siem

router = APIRouter(prefix='/api/v1')


@router.post('/ingestion/logstash', include_in_schema=False)
@router.post('/ingestion/batches', tags=['Ingestion'], summary='دریافت و ذخیرهٔ تکرارپذیر گروه لاگ')
def receive(body: IngestionBatch, database: DB):
    try:
        return ingestion.receive_batch(database, body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get('/ingestion/batches/{batch_id}', tags=['Ingestion'], summary='وضعیت پردازش و ذخیرهٔ گروه لاگ')
def batch_status(batch_id: UUID, database: DB):
    row = database.ingestion_batches.find_one({'_id': str(batch_id)}, {'fingerprint': 0})
    if row is None:
        raise HTTPException(404, 'Batch has not reached this API')
    return siem.public(row)
