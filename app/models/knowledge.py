from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base_model import BaseModel


class KnowledgeDocument(BaseModel):
    """Documento SOC trazable que alimenta la recuperación de Linterna."""

    __tablename__ = "knowledge_documents"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "content_hash",
            name="uq_knowledge_documents_project_hash",
        ),
        CheckConstraint(
            "source_type IN ('playbook', 'runbook', 'standard', 'incident', "
            "'threat_intel', 'note')",
            name="ck_knowledge_documents_source_type",
        ),
        CheckConstraint(
            "status IN ('indexed', 'failed')",
            name="ck_knowledge_documents_status",
        ),
    )

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(
        String(30), nullable=False, index=True
    )
    source_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="indexed", index=True
    )
    embedding_model: Mapped[str] = mapped_column(String(100), nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    document_metadata: Mapped[dict] = mapped_column(
        "metadata", JSON, nullable=False, default=dict
    )

    project = relationship("Project")
    created_by = relationship("User")
    chunks: Mapped[list["KnowledgeChunk"]] = relationship(
        "KnowledgeChunk",
        back_populates="document",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class KnowledgeChunk(BaseModel):
    """Fragmento recuperable con vector y procedencia al documento original."""

    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "position",
            name="uq_knowledge_chunks_document_position",
        ),
        CheckConstraint("position >= 0", name="ck_knowledge_chunks_position"),
        CheckConstraint(
            "character_count > 0", name="ck_knowledge_chunks_character_count"
        ),
    )

    document_id: Mapped[int] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    character_count: Mapped[int] = mapped_column(Integer, nullable=False)
    embedding: Mapped[list] = mapped_column(JSON, nullable=False)

    document: Mapped["KnowledgeDocument"] = relationship(
        "KnowledgeDocument", back_populates="chunks"
    )

