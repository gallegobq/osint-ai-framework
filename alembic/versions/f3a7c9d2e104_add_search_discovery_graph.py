"""add bounded search discovery graph

Revision ID: f3a7c9d2e104
Revises: 7b2e9c4a6f10
Create Date: 2026-10-02
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f3a7c9d2e104"
down_revision: Union[str, Sequence[str], None] = "7b2e9c4a6f10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TARGET_TYPE_CHECK = (
    "target_type IN ('domain', 'hostname', 'ip', 'asn', 'url', "
    "'username', 'email', 'hash', 'cve', 'keyword')"
)


def _add_discovery_policy(table_name: str, prefix: str) -> None:
    op.add_column(
        table_name,
        sa.Column(
            "follow_discoveries",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        table_name,
        sa.Column(
            "discovery_max_depth",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        table_name,
        sa.Column(
            "discovery_max_events",
            sa.Integer(),
            nullable=False,
            server_default="25",
        ),
    )
    op.create_check_constraint(
        f"ck_{prefix}_discovery_max_depth",
        table_name,
        "discovery_max_depth >= 1 AND discovery_max_depth <= 3",
    )
    op.create_check_constraint(
        f"ck_{prefix}_discovery_max_events",
        table_name,
        "discovery_max_events >= 1 AND discovery_max_events <= 100",
    )


def _drop_discovery_policy(table_name: str, prefix: str) -> None:
    op.drop_constraint(
        f"ck_{prefix}_discovery_max_events",
        table_name,
        type_="check",
    )
    op.drop_constraint(
        f"ck_{prefix}_discovery_max_depth",
        table_name,
        type_="check",
    )
    op.drop_column(table_name, "discovery_max_events")
    op.drop_column(table_name, "discovery_max_depth")
    op.drop_column(table_name, "follow_discoveries")


def upgrade() -> None:
    _add_discovery_policy("search_runs", "search_runs")
    _add_discovery_policy("search_schedules", "search_schedules")

    op.create_table(
        "search_discoveries",
        sa.Column("search_run_id", sa.Integer(), nullable=False),
        sa.Column("target_type", sa.String(length=20), nullable=False),
        sa.Column("target_value", sa.Text(), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("min_depth", sa.Integer(), nullable=False, server_default="0"),
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
            TARGET_TYPE_CHECK,
            name="ck_search_discoveries_target_type",
        ),
        sa.CheckConstraint(
            "min_depth >= 0 AND min_depth <= 4",
            name="ck_search_discoveries_min_depth",
        ),
        sa.ForeignKeyConstraint(
            ["search_run_id"],
            ["search_runs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "search_run_id",
            "target_type",
            "value_hash",
            name="uq_search_discoveries_identity",
        ),
    )
    for column in (
        "id",
        "search_run_id",
        "target_type",
        "value_hash",
        "min_depth",
    ):
        op.create_index(
            f"ix_search_discoveries_{column}",
            "search_discoveries",
            [column],
        )

    op.create_table(
        "search_discovery_edges",
        sa.Column("search_run_id", sa.Integer(), nullable=False),
        sa.Column("parent_discovery_id", sa.Integer(), nullable=True),
        sa.Column("child_discovery_id", sa.Integer(), nullable=False),
        sa.Column("collection_job_id", sa.Integer(), nullable=True),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("relation", sa.String(length=100), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_hash", sa.String(length=64), nullable=False),
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
            "depth >= 0 AND depth <= 4",
            name="ck_search_discovery_edges_depth",
        ),
        sa.ForeignKeyConstraint(
            ["child_discovery_id"],
            ["search_discoveries.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["collection_job_id"],
            ["collection_jobs.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["parent_discovery_id"],
            ["search_discoveries.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["search_run_id"],
            ["search_runs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "search_run_id",
            "edge_hash",
            name="uq_search_discovery_edges_identity",
        ),
    )
    for column in (
        "id",
        "search_run_id",
        "parent_discovery_id",
        "child_discovery_id",
        "collection_job_id",
        "evidence_id",
        "depth",
        "edge_hash",
    ):
        op.create_index(
            f"ix_search_discovery_edges_{column}",
            "search_discovery_edges",
            [column],
        )

    op.add_column(
        "collection_jobs",
        sa.Column("input_discovery_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_collection_jobs_input_discovery_id",
        "collection_jobs",
        "search_discoveries",
        ["input_discovery_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_collection_jobs_input_discovery_id",
        "collection_jobs",
        ["input_discovery_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_collection_jobs_input_discovery_id",
        table_name="collection_jobs",
    )
    op.drop_constraint(
        "fk_collection_jobs_input_discovery_id",
        "collection_jobs",
        type_="foreignkey",
    )
    op.drop_column("collection_jobs", "input_discovery_id")

    for column in (
        "edge_hash",
        "depth",
        "evidence_id",
        "collection_job_id",
        "child_discovery_id",
        "parent_discovery_id",
        "search_run_id",
        "id",
    ):
        op.drop_index(
            f"ix_search_discovery_edges_{column}",
            table_name="search_discovery_edges",
        )
    op.drop_table("search_discovery_edges")

    for column in (
        "min_depth",
        "value_hash",
        "target_type",
        "search_run_id",
        "id",
    ):
        op.drop_index(
            f"ix_search_discoveries_{column}",
            table_name="search_discoveries",
        )
    op.drop_table("search_discoveries")

    _drop_discovery_policy("search_schedules", "search_schedules")
    _drop_discovery_policy("search_runs", "search_runs")
