from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class KnowledgeSourceType(StrEnum):
    PLAYBOOK = "playbook"
    RUNBOOK = "runbook"
    STANDARD = "standard"
    INCIDENT = "incident"
    THREAT_INTEL = "threat_intel"
    NOTE = "note"


class KnowledgeDocumentCreate(BaseModel):
    title: str = Field(min_length=2, max_length=255)
    source_type: KnowledgeSourceType
    source_uri: str | None = Field(default=None, max_length=2048)
    content: str = Field(min_length=50)
    metadata: dict = Field(default_factory=dict)


class KnowledgeDocumentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    created_by_id: int
    title: str
    source_type: KnowledgeSourceType
    source_uri: str | None
    content_hash: str
    status: str
    embedding_model: str
    chunk_count: int
    document_metadata: dict
    created_at: datetime
    updated_at: datetime


class RagQuery(BaseModel):
    question: str = Field(min_length=5, max_length=4000)
    top_k: int = Field(default=6, ge=1, le=12)
    minimum_score: float = Field(default=0.15, ge=0, le=1)


class RagCitationRead(BaseModel):
    chunk_id: int
    document_id: int
    document_title: str
    source_type: KnowledgeSourceType
    source_uri: str | None
    claim: str
    score: float


class RagQueryResult(BaseModel):
    answer: str
    citations: list[RagCitationRead]
    confidence: float = Field(ge=0, le=1)
    gaps: list[str]
    embedding_model: str
    human_review_required: bool = True

