from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.schemas.log import LogCreate

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Description = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
Severity = Literal['low', 'medium', 'high', 'critical']
AlertStatus = Literal['open', 'acknowledged', 'resolved']
IncidentStatus = Literal['open', 'investigating', 'contained', 'closed']


class StrictBody(BaseModel):
    model_config = ConfigDict(extra='forbid')


class AlertCreate(StrictBody):
    title: Name
    description: Description
    severity: Severity = 'medium'
    source: Name = 'manual'
    event_ids: list[UUID] = Field(default_factory=list, max_length=100)


class AlertUpdate(StrictBody):
    status: AlertStatus


class RuleCreate(StrictBody):
    name: Name
    description: Description
    enabled: bool = True
    severity: Severity = 'high'
    source: Name | None = None
    level: Literal['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'] | None = None
    threshold: int = Field(default=10, ge=1, le=1000000)
    lookback_seconds: int = Field(default=300, ge=10, le=86400)
    cooldown_seconds: int = Field(default=300, ge=10, le=86400, description="Fixed UTC deduplication bucket in seconds; a boundary can start a new alert bucket")


class RuleToggle(StrictBody):
    enabled: bool


class IncidentCreate(StrictBody):
    title: Name
    description: Description
    severity: Severity = 'high'
    alert_ids: list[UUID] = Field(default_factory=list, max_length=100)


class IncidentUpdate(StrictBody):
    status: IncidentStatus


class IncidentNote(StrictBody):
    text: Description


class PredictionAlerts(StrictBody):
    min_probability: float = Field(default=0.9, gt=0, le=1)
    limit: int = Field(default=500, ge=1, le=1000)


class IngestionBatch(StrictBody):
    batch_id: UUID = Field(default_factory=uuid4)
    events: list[LogCreate] = Field(min_length=1, max_length=500)
