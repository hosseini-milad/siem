from pymongo.database import Database

from app.models.log import COLLECTION, log_document, public_document
from app.schemas.log import LogCreate
from app.services import search


def store_logs(database: Database, events: list[LogCreate]) -> list[dict]:
    rows = [log_document(event) for event in events]
    database[COLLECTION].insert_many(rows, ordered=True)
    return [public_document(row) for row in rows]


def list_logs(database: Database, *, source, level, start, end, limit: int, offset: int):
    query = search.event_filter(source=source, level=level, start=start, end=end)
    return search.page(database, query, limit, offset)


def find_log(database: Database, log_id: str):
    row = database[COLLECTION].find_one({"_id": log_id})
    return public_document(row) if row else None
