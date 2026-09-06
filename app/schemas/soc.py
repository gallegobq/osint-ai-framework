from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.orchestration import SearchTarget


class FindingSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class FindingCreate(BaseModel):
    evidence_id: int | None = Field(default=None, gt=0)
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=3, max_length=20000)
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: Decimal = Field(default=Decimal("0.500"), ge=0, le=1)
    remediation: str | None = Field(default=None, max_length=20000)
    due_at: datetime | None = None


class FindingUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, min_length=3, max_length=20000)
    severity: FindingSeverity | None = None
    status: FindingStatus | None = None
    confidence: Decimal | None = Field(default=None, ge=0, le=1)
    remediation: str | None = Field(default=None, max_length=20000)
    due_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_required_nulls(cls, data: object) -> object:
        if isinstance(data, dict):
            invalid = {
                field
                for field in ("title", "description", "severity", "status", "confidence")
                if field in data and data[field] is None
            }
            if invalid:
                raise ValueError(
                    "The following fields cannot be null: "
                    + ", ".join(sorted(invalid))
                    + "."
                )
        return data

    @model_validator(mode="after")
    def require_change(self) -> "FindingUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    evidence_id: int | None
    created_by_id: int
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus
    confidence: Decimal
    remediation: str | None
    due_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime


class SearchScheduleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    objective: str = Field(min_length=5, max_length=2000)
    targets: list[SearchTarget] = Field(min_length=1, max_length=20)
    max_tools: int = Field(default=20, ge=1, le=50)
    interval_minutes: int = Field(default=1440, ge=15, le=43200)
    authorization_confirmed: bool
    authorization_scope: str = Field(min_length=10, max_length=5000)
    enabled: bool = True

    @model_validator(mode="after")
    def require_authorization(self) -> "SearchScheduleCreate":
        if not self.authorization_confirmed:
            raise ValueError("Scheduled searches require authorization confirmation.")
        return self


class SearchScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=200)
    objective: str | None = Field(default=None, min_length=5, max_length=2000)
    targets: list[SearchTarget] | None = Field(default=None, min_length=1, max_length=20)
    max_tools: int | None = Field(default=None, ge=1, le=50)
    interval_minutes: int | None = Field(default=None, ge=15, le=43200)
    authorization_scope: str | None = Field(default=None, min_length=10, max_length=5000)
    enabled: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_required_nulls(cls, data: object) -> object:
        if isinstance(data, dict):
            invalid = {
                field
                for field in (
                    "name",
                    "objective",
                    "targets",
                    "max_tools",
                    "interval_minutes",
                    "authorization_scope",
                    "enabled",
                )
                if field in data and data[field] is None
            }
            if invalid:
                raise ValueError(
                    "The following fields cannot be null: "
                    + ", ".join(sorted(invalid))
                    + "."
                )
        return data

    @model_validator(mode="after")
    def require_change(self) -> "SearchScheduleUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class SearchScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    created_by_id: int
    name: str
    objective: str
    targets: list[dict]
    max_tools: int
    interval_minutes: int
    authorization_scope: str
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_search_run_id: int | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime
