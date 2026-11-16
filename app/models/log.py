from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.schemas.log import LogCreate


COLLECTION = "log_events"


def log_document(event: LogCreate) -> dict[str, Any]:
    """Build the persistence document independently of HTTP routing."""
    now = datetime.now(timezone.utc)
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    return {
        "_id": str(uuid4()),
        **event.model_dump(mode="python"),
        "received_at": now,
    }


def public_document(document: dict[str, Any]) -> dict[str, Any]:
    return {"id": document["_id"], **{k: v for k, v in document.items() if k != "_id"}}
