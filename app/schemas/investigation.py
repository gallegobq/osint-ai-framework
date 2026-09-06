from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InvestigationKind(StrEnum):
    PERSON = "person"
    COMPANY = "company"
    DOMAIN = "domain"
    MIXED = "mixed"


class InvestigationMode(StrEnum):
    ATTACK_SURFACE = "attack_surface"
    INCIDENT_RESPONSE = "incident_response"
    PENTEST = "pentest"


class InvestigationStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class Priority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(StrEnum):
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    kind: InvestigationKind = InvestigationKind.MIXED
    priority: Priority = Priority.MEDIUM
    operation_mode: InvestigationMode = InvestigationMode.ATTACK_SURFACE
    authorization_scope: str | None = Field(default=None, max_length=5000)
    active_testing_authorized: bool = False
    engagement_start_at: datetime | None = None
    engagement_end_at: datetime | None = None
    jurisdiction: str | None = Field(default=None, max_length=100)
    legal_basis: str | None = Field(default=None, max_length=5000)
    data_classification: DataClassification = DataClassification.INTERNAL
    retention_until: datetime | None = None

    @model_validator(mode="after")
    def validate_operation_mode(self) -> "InvestigationCreate":
        if self.retention_until is not None:
            if self.retention_until.utcoffset() is None:
                raise ValueError("Retention timestamp must include a timezone.")
            if self.retention_until <= datetime.now(self.retention_until.tzinfo):
                raise ValueError("Retention timestamp must be in the future.")
        has_window = (
            self.engagement_start_at is not None
            or self.engagement_end_at is not None
        )
        if self.operation_mode != InvestigationMode.PENTEST:
            if self.active_testing_authorized or has_window:
                raise ValueError(
                    "Active authorization and engagement windows are only "
                    "valid for pentest investigations."
                )
            return self

        scope = (self.authorization_scope or "").strip()
        if len(scope) < 20:
            raise ValueError(
                "Pentest investigations require a detailed authorization scope."
            )
        if not self.active_testing_authorized:
            raise ValueError(
                "Pentest investigations require explicit active-testing authorization."
            )
        if self.engagement_start_at is None or self.engagement_end_at is None:
            raise ValueError(
                "Pentest investigations require a complete engagement window."
            )
        if (
            self.engagement_start_at.utcoffset() is None
            or self.engagement_end_at.utcoffset() is None
        ):
            raise ValueError("Engagement timestamps must include a timezone.")
        if self.engagement_end_at <= self.engagement_start_at:
            raise ValueError("Engagement end must be after its start.")
        self.authorization_scope = scope
        return self


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    status: InvestigationStatus | None = None
    priority: Priority | None = None
    jurisdiction: str | None = Field(default=None, max_length=100)
    legal_basis: str | None = Field(default=None, max_length=5000)
    data_classification: DataClassification | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_non_nullable_nulls(cls, data: object) -> object:
        if isinstance(data, dict):
            invalid = {
                field
                for field in (
                    "title",
                    "status",
                    "priority",
                    "data_classification",
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
    def require_change(self) -> "InvestigationUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class RetentionPolicyUpdate(BaseModel):
    retention_until: datetime | None = None
    legal_hold: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_null_hold(cls, data: object) -> object:
        if isinstance(data, dict) and data.get("legal_hold", True) is None:
            raise ValueError("legal_hold cannot be null.")
        return data

    @model_validator(mode="after")
    def validate_policy(self) -> "RetentionPolicyUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        if self.retention_until is not None:
            if self.retention_until.utcoffset() is None:
                raise ValueError("Retention timestamp must include a timezone.")
            if self.retention_until <= datetime.now(self.retention_until.tzinfo):
                raise ValueError("Retention timestamp must be in the future.")
        return self


class InvestigationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    created_by_id: int
    title: str
    description: str | None
    kind: InvestigationKind
    status: InvestigationStatus
    priority: Priority
    operation_mode: InvestigationMode
    authorization_scope: str | None
    active_testing_authorized: bool
    engagement_start_at: datetime | None
    engagement_end_at: datetime | None
    jurisdiction: str | None
    legal_basis: str | None
    data_classification: DataClassification
    retention_until: datetime | None
    legal_hold: bool
    created_at: datetime
    updated_at: datetime


class InvestigationTaskCreate(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    priority: Priority = Priority.MEDIUM
    assignee_id: int | None = Field(default=None, gt=0)
    due_at: datetime | None = None


class InvestigationTaskUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    status: TaskStatus | None = None
    priority: Priority | None = None
    assignee_id: int | None = Field(default=None, gt=0)
    due_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_non_nullable_nulls(cls, data: object) -> object:
        if isinstance(data, dict):
            invalid = {
                field
                for field in ("title", "status", "priority")
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
    def require_change(self) -> "InvestigationTaskUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class InvestigationTaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    assignee_id: int | None
    title: str
    description: str | None
    status: TaskStatus
    priority: Priority
    due_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
