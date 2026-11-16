from pymongo.database import Database

from app.models.log import COLLECTION, log_document, public_document
from app.schemas.log import LogCreate


def store_logs(database: Database, events: list[LogCreate]) -> list[dict]:
    rows = [log_document(event) for event in events]
    database[COLLECTION].insert_many(rows, ordered=True)
    return [public_document(row) for row in rows]


def list_logs(database: Database, *, source, level, start, end, limit: int, offset: int):
    query = {}
    if source is not None:
        query["source"] = source
    if level is not None:
        query["level"] = level.value
    if start is not None or end is not None:
        query["timestamp"] = {}
        if start is not None:
            query["timestamp"]["$gte"] = start
        if end is not None:
            query["timestamp"]["$lte"] = end
    collection = database[COLLECTION]
    total = collection.count_documents(query)
    rows = collection.find(query).sort([("timestamp", -1), ("_id", -1)]).skip(offset).limit(limit)
    return {"items": [public_document(row) for row in rows], "total": total, "limit": limit, "offset": offset}


def find_log(database: Database, log_id: str):
    row = database[COLLECTION].find_one({"_id": log_id})
    return public_document(row) if row else None
