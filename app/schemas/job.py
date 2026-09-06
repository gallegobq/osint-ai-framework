from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CollectionJobCreate(BaseModel):
    collector: str = Field(min_length=2, max_length=50)
    query: dict


class CollectionJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    requested_by_id: int
    collector: str
    query: dict
    status: JobStatus
    attempts: int
    result_summary: dict | None
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class AnalysisType(StrEnum):
    SUMMARY = "summary"
    ENTITIES = "entities"
    RELATIONS = "relations"
    SENTIMENT = "sentiment"


class AnalysisJobCreate(BaseModel):
    analysis_type: AnalysisType


class AnalysisJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    requested_by_id: int
    analysis_type: AnalysisType
    provider: str
    prompt_version: str
    status: JobStatus
    result: dict | None
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
