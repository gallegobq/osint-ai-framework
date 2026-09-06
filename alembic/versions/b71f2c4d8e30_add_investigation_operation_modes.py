"""add investigation operation modes

Revision ID: b71f2c4d8e30
Revises: f13c9e0b4a21
Create Date: 2026-08-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b71f2c4d8e30"
down_revision: Union[str, Sequence[str], None] = "f13c9e0b4a21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column(
            "operation_mode",
            sa.String(length=30),
            server_default="attack_surface",
            nullable=False,
        ),
    )
    op.add_column(
        "investigations",
        sa.Column("authorization_scope", sa.Text(), nullable=True),
    )
    op.add_column(
        "investigations",
        sa.Column(
            "active_testing_authorized",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.add_column(
        "investigations",
        sa.Column("engagement_start_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "investigations",
        sa.Column("engagement_end_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_investigations_operation_mode",
        "investigations",
        ["operation_mode"],
    )
    op.create_check_constraint(
        "ck_investigations_operation_mode",
        "investigations",
        "operation_mode IN ('attack_surface', 'incident_response', 'pentest')",
    )
    op.create_check_constraint(
        "ck_investigations_active_requires_pentest",
        "investigations",
        "active_testing_authorized = false OR operation_mode = 'pentest'",
    )
    op.create_check_constraint(
        "ck_investigations_engagement_window",
        "investigations",
        "(engagement_start_at IS NULL AND engagement_end_at IS NULL) OR "
        "(engagement_start_at IS NOT NULL AND engagement_end_at IS NOT NULL "
        "AND engagement_end_at > engagement_start_at)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_investigations_engagement_window",
        "investigations",
        type_="check",
    )
    op.drop_constraint(
        "ck_investigations_active_requires_pentest",
        "investigations",
        type_="check",
    )
    op.drop_constraint(
        "ck_investigations_operation_mode",
        "investigations",
        type_="check",
    )
    op.drop_index("ix_investigations_operation_mode", table_name="investigations")
    op.drop_column("investigations", "engagement_end_at")
    op.drop_column("investigations", "engagement_start_at")
    op.drop_column("investigations", "active_testing_authorized")
    op.drop_column("investigations", "authorization_scope")
    op.drop_column("investigations", "operation_mode")
