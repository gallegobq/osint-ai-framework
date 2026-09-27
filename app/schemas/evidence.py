import json
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _bounded_json_object(
    value: dict,
    *,
    field_name: str,
    max_bytes: int,
    max_depth: int = 32,
    max_items: int = 10_000,
) -> dict:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must contain valid JSON values.") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{field_name} exceeds its encoded size limit.")

    pending: list[tuple[Any, int]] = [(value, 1)]
    item_count = 0
    while pending:
        current, depth = pending.pop()
        if depth > max_depth:
            raise ValueError(f"{field_name} exceeds its nesting limit.")
        if isinstance(current, dict):
            item_count += len(current)
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            item_count += len(current)
            pending.extend((item, depth + 1) for item in current)
        if item_count > max_items:
            raise ValueError(f"{field_name} contains too many items.")
    return value


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

    @field_validator("source_metadata")
    @classmethod
    def validate_source_metadata(cls, value: dict) -> dict:
        return _bounded_json_object(
            value,
            field_name="source_metadata",
            max_bytes=100_000,
        )

    @field_validator("raw_data")
    @classmethod
    def validate_raw_data(cls, value: dict) -> dict:
        return _bounded_json_object(
            value,
            field_name="raw_data",
            max_bytes=1_000_000,
        )


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
    integrity_signature: str | None = None
    integrity_version: int = 1
    integrity_key_id: str = "legacy-secret-key"
    observed_at: datetime | None
    collected_at: datetime
    raw_data: dict
    source: EvidenceSourceRead | None = None
    created_at: datetime


class EvidenceIntegrityVerification(BaseModel):
    evidence_id: int
    valid: bool
    content_hash_valid: bool
    signature_valid: bool
    integrity_version: int
    scheme: Literal["legacy-v1", "canonical-v2", "unknown"]
    key_id: str
    key_available: bool
    verified_at: datetime
    warnings: list[str] = Field(default_factory=list)


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
