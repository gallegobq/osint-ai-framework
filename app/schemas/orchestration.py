from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.osint.profiles import ScanProfile


class SearchTargetType(StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    USERNAME = "username"
    EMAIL = "email"
    HASH = "hash"
    CVE = "cve"
    KEYWORD = "keyword"


class SearchTarget(BaseModel):
    type: SearchTargetType
    value: str = Field(min_length=1, max_length=2048)


class SearchRunCreate(BaseModel):
    objective: str = Field(min_length=5, max_length=2000)
    targets: list[SearchTarget] = Field(default_factory=list, max_length=20)
    profile: ScanProfile = ScanProfile.AUTO
    max_tools: int = Field(default=40, ge=1, le=50)
    allow_active: bool = False
    follow_discoveries: bool = False
    discovery_max_depth: int = Field(default=1, ge=1, le=3)
    discovery_max_events: int = Field(default=25, ge=1, le=100)
    authorization_confirmed: bool
    scope_note: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def require_authorized_scope(self) -> "SearchRunCreate":
        if not self.authorization_confirmed:
            raise ValueError(
                "You must confirm that the targets are authorized for research."
            )
        return self


class ProposedPlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector: str = Field(min_length=2, max_length=50)
    target_index: int = Field(ge=0)
    reason: str = Field(min_length=2, max_length=300)


class ProposedSearchPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=2, max_length=1000)
    steps: list[ProposedPlanStep] = Field(min_length=1, max_length=50)


class SearchRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class SearchRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    requested_by_id: int
    objective: str
    targets: list[dict]
    profile: ScanProfile
    max_tools: int
    allow_active: bool
    follow_discoveries: bool
    discovery_max_depth: int
    discovery_max_events: int
    policy: dict
    status: SearchRunStatus
    planner: str | None
    plan: dict | None
    result_summary: dict | None
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ChatSearchCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(min_length=1, max_length=2000)
    parent_run_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False


class ChatSearchRead(BaseModel):
    message: str
    analysis_type: str
    decisions: list[str]
    needs_clarification: bool
    run: SearchRunRead | None = None


class ScanProfileRead(BaseModel):
    name: ScanProfile
    label: str
    description: str
    deterministic: bool
    passive_only: bool


class SearchDiscoveryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    search_run_id: int
    target_type: SearchTargetType
    target_value: str
    min_depth: int
    created_at: datetime


class SearchDiscoveryEdgeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    search_run_id: int
    parent_discovery_id: int | None
    child_discovery_id: int
    collection_job_id: int | None
    evidence_id: int | None
    relation: str
    depth: int
    created_at: datetime


class SearchDiscoveryGraphRead(BaseModel):
    nodes: list[SearchDiscoveryRead]
    edges: list[SearchDiscoveryEdgeRead]
