"""add search orchestration

Revision ID: f13c9e0b4a21
Revises: d84f3c9a1b72
Create Date: 2026-08-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f13c9e0b4a21"
down_revision: Union[str, Sequence[str], None] = "d84f3c9a1b72"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "search_runs",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("max_tools", sa.Integer(), nullable=False),
        sa.Column("allow_active", sa.Boolean(), nullable=False),
        sa.Column("policy", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("planner", sa.String(length=50), nullable=True),
        sa.Column("plan", sa.JSON(), nullable=True),
        sa.Column("result_summary", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'partial', 'failed')",
            name="ck_search_runs_status",
        ),
        sa.CheckConstraint("max_tools >= 1", name="ck_search_runs_max_tools"),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_search_runs_id", "search_runs", ["id"])
    op.create_index(
        "ix_search_runs_investigation_id",
        "search_runs",
        ["investigation_id"],
    )
    op.create_index(
        "ix_search_runs_requested_by_id",
        "search_runs",
        ["requested_by_id"],
    )
    op.create_index("ix_search_runs_status", "search_runs", ["status"])

    op.add_column(
        "collection_jobs",
        sa.Column("search_run_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_collection_jobs_search_run_id",
        "collection_jobs",
        "search_runs",
        ["search_run_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_collection_jobs_search_run_id",
        "collection_jobs",
        ["search_run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_collection_jobs_search_run_id",
        table_name="collection_jobs",
    )
    op.drop_constraint(
        "fk_collection_jobs_search_run_id",
        "collection_jobs",
        type_="foreignkey",
    )
    op.drop_column("collection_jobs", "search_run_id")
    op.drop_table("search_runs")
