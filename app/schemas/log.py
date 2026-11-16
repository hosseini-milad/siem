from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Annotated
from uuid import UUID

from bson import BSON
from bson.errors import InvalidDocument
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, field_validator


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": {
        "timestamp": "2026-11-16T10:00:00Z", "source": "firewall-01", "level": "WARNING",
        "message": "Connection denied", "attributes": {"source_ip": "192.0.2.10", "port": 22}
    }})
    timestamp: AwareDatetime
    source: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
    level: LogLevel = LogLevel.INFO
    message: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=65536)]
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def valid_attributes(cls, value):
        try:
            encoded = BSON.encode({"attributes": value})
        except (InvalidDocument, OverflowError, ValueError, RecursionError) as exc:
            raise ValueError("attributes must be BSON-compatible JSON") from exc
        if len(encoded) > 1048576:
            raise ValueError("attributes must be at most 1 MiB")
        return value

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        value = value.astimezone(timezone.utc)
        return value.replace(microsecond=(value.microsecond // 1000) * 1000)


class LogRead(LogCreate):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    received_at: AwareDatetime



class LogBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[LogCreate] = Field(min_length=1, max_length=500)


class LogPage(BaseModel):
    items: list[LogRead]
    total: int
    limit: int
    offset: int
