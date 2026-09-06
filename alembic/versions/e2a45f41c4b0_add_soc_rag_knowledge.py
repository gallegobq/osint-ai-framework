"""add project-scoped SOC RAG knowledge

Revision ID: e2a45f41c4b0
Revises: c84f7a2e9d10
Create Date: 2026-08-31
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e2a45f41c4b0"
down_revision: Union[str, Sequence[str], None] = "c84f7a2e9d10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "knowledge_documents",
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=30), nullable=False),
        sa.Column("source_uri", sa.String(length=2048), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default="indexed",
            nullable=False,
        ),
        sa.Column("embedding_model", sa.String(length=100), nullable=False),
        sa.Column(
            "chunk_count", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("metadata", sa.JSON(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "source_type IN ('playbook', 'runbook', 'standard', 'incident', "
            "'threat_intel', 'note')",
            name="ck_knowledge_documents_source_type",
        ),
        sa.CheckConstraint(
            "status IN ('indexed', 'failed')",
            name="ck_knowledge_documents_status",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "content_hash",
            name="uq_knowledge_documents_project_hash",
        ),
    )
    for column in (
        "id",
        "project_id",
        "created_by_id",
        "source_type",
        "content_hash",
        "status",
    ):
        op.create_index(
            f"ix_knowledge_documents_{column}",
            "knowledge_documents",
            [column],
        )

    op.create_table(
        "knowledge_chunks",
        sa.Column("document_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("character_count", sa.Integer(), nullable=False),
        sa.Column("embedding", sa.JSON(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "position >= 0", name="ck_knowledge_chunks_position"
        ),
        sa.CheckConstraint(
            "character_count > 0",
            name="ck_knowledge_chunks_character_count",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"], ["knowledge_documents.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "document_id",
            "position",
            name="uq_knowledge_chunks_document_position",
        ),
    )
    for column in ("id", "document_id", "project_id", "content_hash"):
        op.create_index(
            f"ix_knowledge_chunks_{column}", "knowledge_chunks", [column]
        )


def downgrade() -> None:
    op.drop_table("knowledge_chunks")
    op.drop_table("knowledge_documents")

