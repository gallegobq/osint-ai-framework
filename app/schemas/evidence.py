from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field


class EvidenceCreate(BaseModel):
    collector: str = Field(min_length=2, max_length=50)
    source_type: str = Field(min_length=2, max_length=50)
    locator: str = Field(min_length=1, max_length=2048)
    source_metadata: dict = Field(default_factory=dict)
    kind: str = Field(min_length=2, max_length=50)
    title: str = Field(min_length=2, max_length=255)
    content: str = Field(min_length=1, max_length=1_000_000)
    observed_at: datetime | None = None
    raw_data: dict = Field(default_factory=dict)


class EvidenceSourceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    collector: str
    source_type: str
    locator: str
    collected_at: datetime
    source_metadata: dict


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    source_id: int
    created_by_id: int | None
    kind: str
    title: str
    content: str
    content_hash: str
    observed_at: datetime | None
    collected_at: datetime
    raw_data: dict
    created_at: datetime


class EntityCreate(BaseModel):
    entity_type: str = Field(min_length=2, max_length=50)
    canonical_name: str = Field(min_length=1, max_length=255)
    confidence: Decimal = Field(default=Decimal("1.0"), ge=0, le=1)
    attributes: dict = Field(default_factory=dict)


class EntityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    entity_type: str
    canonical_name: str
    confidence: Decimal
    attributes: dict
    created_at: datetime


class EntityRelationCreate(BaseModel):
    source_entity_id: int = Field(gt=0)
    target_entity_id: int = Field(gt=0)
    evidence_id: int | None = Field(default=None, gt=0)
    relation_type: str = Field(min_length=2, max_length=100)
    confidence: Decimal = Field(default=Decimal("1.0"), ge=0, le=1)
    attributes: dict = Field(default_factory=dict)


class EntityRelationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    source_entity_id: int
    target_entity_id: int
    evidence_id: int | None
    relation_type: str
    confidence: Decimal
    attributes: dict
    created_at: datetime
