from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    JSON,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base_model import BaseModel


class EvidenceSource(BaseModel):
    __tablename__ = "evidence_sources"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "collector",
            "locator_hash",
            name="uq_evidence_sources_identity",
        ),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    collector: Mapped[str] = mapped_column(String(50), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    locator: Mapped[str] = mapped_column(String(2048), nullable=False)
    locator_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    source_metadata: Mapped[dict] = mapped_column(
        "metadata", JSON, nullable=False, default=dict
    )

    investigation = relationship("Investigation")
    evidence: Mapped[list["Evidence"]] = relationship(
        "Evidence",
        back_populates="source",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Evidence(BaseModel):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "content_hash",
            name="uq_evidence_investigation_hash",
        ),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[int] = mapped_column(
        ForeignKey("evidence_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    source: Mapped["EvidenceSource"] = relationship(
        "EvidenceSource", back_populates="evidence"
    )
    created_by = relationship("User", foreign_keys=[created_by_id])


class Entity(BaseModel):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "entity_type",
            "canonical_name",
            name="uq_entities_investigation_identity",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_entities_confidence",
        ),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    canonical_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(5, 4), nullable=False, default=Decimal("1.0")
    )
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    investigation = relationship("Investigation")


class EntityRelation(BaseModel):
    __tablename__ = "entity_relations"
    __table_args__ = (
        UniqueConstraint(
            "source_entity_id",
            "target_entity_id",
            "relation_type",
            name="uq_entity_relations_identity",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_entity_relations_confidence",
        ),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_entity_id: Mapped[int] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_entity_id: Mapped[int] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    relation_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(5, 4), nullable=False, default=Decimal("1.0")
    )
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    source_entity = relationship("Entity", foreign_keys=[source_entity_id])
    target_entity = relationship("Entity", foreign_keys=[target_entity_id])
    evidence = relationship("Evidence")
