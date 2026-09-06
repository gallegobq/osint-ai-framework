"""add OSINT domain

Revision ID: d84f3c9a1b72
Revises: c71db15a2e0f
Create Date: 2026-08-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d84f3c9a1b72"
down_revision: Union[str, Sequence[str], None] = "c71db15a2e0f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def base_columns() -> list[sa.Column]:
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


def common_indexes(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_id"), table, ["id"], unique=False)


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("slug", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "status IN ('active', 'archived')",
            name="ck_projects_status",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    common_indexes("projects")
    op.create_index("ix_projects_slug", "projects", ["slug"], unique=True)
    op.create_index("ix_projects_status", "projects", ["status"])
    op.create_index("ix_projects_owner_id", "projects", ["owner_id"])

    op.create_table(
        "project_members",
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "user_id",
            name="uq_project_members_project_user",
        ),
        sa.CheckConstraint(
            "role IN ('viewer', 'editor', 'owner')",
            name="ck_project_members_role",
        ),
    )
    common_indexes("project_members")
    op.create_index(
        "ix_project_members_project_id", "project_members", ["project_id"]
    )
    op.create_index(
        "ix_project_members_user_id", "project_members", ["user_id"]
    )
    op.create_index("ix_project_members_role", "project_members", ["role"])

    op.create_table(
        "investigations",
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("priority", sa.String(length=20), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "kind IN ('person', 'company', 'domain', 'mixed')",
            name="ck_investigations_kind",
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'active', 'paused', 'completed', 'archived')",
            name="ck_investigations_status",
        ),
        sa.CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_investigations_priority",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    common_indexes("investigations")
    for column in (
        "project_id",
        "created_by_id",
        "kind",
        "status",
        "priority",
    ):
        op.create_index(
            f"ix_investigations_{column}", "investigations", [column]
        )

    op.create_table(
        "investigation_tasks",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("assignee_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("priority", sa.String(length=20), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["assignee_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.CheckConstraint(
            "status IN ('todo', 'in_progress', 'blocked', 'done')",
            name="ck_investigation_tasks_status",
        ),
        sa.CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_investigation_tasks_priority",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    common_indexes("investigation_tasks")
    for column in ("investigation_id", "assignee_id", "status", "priority"):
        op.create_index(
            f"ix_investigation_tasks_{column}",
            "investigation_tasks",
            [column],
        )

    op.create_table(
        "evidence_sources",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("collector", sa.String(length=50), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("locator", sa.String(length=2048), nullable=False),
        sa.Column("locator_hash", sa.String(length=64), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            "collector",
            "locator_hash",
            name="uq_evidence_sources_identity",
        ),
    )
    common_indexes("evidence_sources")
    op.create_index(
        "ix_evidence_sources_investigation_id",
        "evidence_sources",
        ["investigation_id"],
    )
    op.create_index(
        "ix_evidence_sources_locator_hash",
        "evidence_sources",
        ["locator_hash"],
    )

    op.create_table(
        "evidence",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_data", sa.JSON(), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["evidence_sources.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            "content_hash",
            name="uq_evidence_investigation_hash",
        ),
    )
    common_indexes("evidence")
    for column in (
        "investigation_id",
        "source_id",
        "created_by_id",
        "kind",
        "content_hash",
    ):
        op.create_index(f"ix_evidence_{column}", "evidence", [column])

    op.create_table(
        "entities",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("canonical_name", sa.String(length=255), nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            "entity_type",
            "canonical_name",
            name="uq_entities_investigation_identity",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_entities_confidence",
        ),
    )
    common_indexes("entities")
    for column in ("investigation_id", "entity_type", "canonical_name"):
        op.create_index(f"ix_entities_{column}", "entities", [column])

    op.create_table(
        "entity_relations",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("source_entity_id", sa.Integer(), nullable=False),
        sa.Column("target_entity_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("relation_type", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_entity_id"], ["entities.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["target_entity_id"], ["entities.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"], ["evidence.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_entity_id",
            "target_entity_id",
            "relation_type",
            name="uq_entity_relations_identity",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_entity_relations_confidence",
        ),
    )
    common_indexes("entity_relations")
    op.create_index(
        "ix_entity_relations_investigation_id",
        "entity_relations",
        ["investigation_id"],
    )
    op.create_index(
        "ix_entity_relations_relation_type",
        "entity_relations",
        ["relation_type"],
    )
    for column in ("source_entity_id", "target_entity_id", "evidence_id"):
        op.create_index(
            f"ix_entity_relations_{column}", "entity_relations", [column]
        )

    op.create_table(
        "collection_jobs",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), nullable=False),
        sa.Column("collector", sa.String(length=50), nullable=False),
        sa.Column("query", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("result_summary", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed')",
            name="ck_collection_jobs_status",
        ),
        sa.CheckConstraint(
            "attempts >= 0",
            name="ck_collection_jobs_attempts",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    common_indexes("collection_jobs")
    for column in ("investigation_id", "requested_by_id", "status"):
        op.create_index(
            f"ix_collection_jobs_{column}", "collection_jobs", [column]
        )

    op.create_table(
        "analysis_jobs",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), nullable=False),
        sa.Column("analysis_type", sa.String(length=30), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("prompt_version", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "analysis_type IN ('summary', 'entities', 'relations', 'sentiment')",
            name="ck_analysis_jobs_type",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed')",
            name="ck_analysis_jobs_status",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    common_indexes("analysis_jobs")
    for column in ("investigation_id", "requested_by_id", "status"):
        op.create_index(
            f"ix_analysis_jobs_{column}", "analysis_jobs", [column]
        )

    op.create_table(
        "audit_events",
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=False),
        sa.Column("resource_id", sa.String(length=100), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        *base_columns(),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    common_indexes("audit_events")
    for column in ("actor_user_id", "action", "resource_type", "resource_id"):
        op.create_index(
            f"ix_audit_events_{column}", "audit_events", [column]
        )


def downgrade() -> None:
    for table in (
        "audit_events",
        "analysis_jobs",
        "collection_jobs",
        "entity_relations",
        "entities",
        "evidence",
        "evidence_sources",
        "investigation_tasks",
        "investigations",
        "project_members",
        "projects",
    ):
        op.drop_table(table)
