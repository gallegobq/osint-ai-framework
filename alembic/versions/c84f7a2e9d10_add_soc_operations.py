"""add SOC findings and scheduled searches

Revision ID: c84f7a2e9d10
Revises: b71f2c4d8e30
Create Date: 2026-08-16
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c84f7a2e9d10"
down_revision: Union[str, Sequence[str], None] = "b71f2c4d8e30"
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
    op.add_column(
        "users",
        sa.Column(
            "mfa_enabled", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column(
        "users", sa.Column("mfa_secret", sa.String(length=512), nullable=True)
    )
    op.add_column(
        "users",
        sa.Column("mfa_confirmed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "investigations",
        sa.Column("jurisdiction", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "investigations", sa.Column("legal_basis", sa.Text(), nullable=True)
    )
    op.add_column(
        "investigations",
        sa.Column(
            "data_classification",
            sa.String(length=20),
            server_default="internal",
            nullable=False,
        ),
    )
    op.add_column(
        "investigations",
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "investigations",
        sa.Column(
            "legal_hold", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.create_check_constraint(
        "ck_investigations_data_classification",
        "investigations",
        "data_classification IN ('public', 'internal', 'confidential', 'restricted')",
    )
    op.create_index(
        "ix_investigations_data_classification",
        "investigations",
        ["data_classification"],
    )
    op.create_index(
        "ix_investigations_retention_until",
        "investigations",
        ["retention_until"],
    )

    op.create_table(
        "findings",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "severity",
            sa.String(length=20),
            server_default="medium",
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default="open",
            nullable=False,
        ),
        sa.Column(
            "confidence",
            sa.Numeric(precision=4, scale=3),
            server_default="0.500",
            nullable=False,
        ),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'triaged', 'in_progress', 'accepted', "
            "'resolved', 'false_positive')",
            name="ck_findings_status",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_findings_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"], ["evidence.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "id",
        "investigation_id",
        "evidence_id",
        "created_by_id",
        "severity",
        "status",
    ):
        op.create_index(f"ix_findings_{column}", "findings", [column])

    op.create_table(
        "search_schedules",
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("max_tools", sa.Integer(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("authorization_scope", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_search_run_id", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "interval_minutes >= 15 AND interval_minutes <= 43200",
            name="ck_search_schedules_interval",
        ),
        sa.CheckConstraint(
            "max_tools >= 1 AND max_tools <= 50",
            name="ck_search_schedules_max_tools",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["last_search_run_id"], ["search_runs.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("id", "investigation_id", "created_by_id", "next_run_at"):
        op.create_index(
            f"ix_search_schedules_{column}", "search_schedules", [column]
        )


def downgrade() -> None:
    op.drop_table("search_schedules")
    op.drop_table("findings")
    op.drop_index(
        "ix_investigations_retention_until", table_name="investigations"
    )
    op.drop_index(
        "ix_investigations_data_classification", table_name="investigations"
    )
    op.drop_constraint(
        "ck_investigations_data_classification",
        "investigations",
        type_="check",
    )
    op.drop_column("investigations", "legal_hold")
    op.drop_column("investigations", "retention_until")
    op.drop_column("investigations", "data_classification")
    op.drop_column("investigations", "legal_basis")
    op.drop_column("investigations", "jurisdiction")
    op.drop_column("users", "mfa_confirmed_at")
    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "mfa_enabled")
