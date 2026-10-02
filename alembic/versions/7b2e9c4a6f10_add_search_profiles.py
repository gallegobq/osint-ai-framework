"""add reproducible search profiles

Revision ID: 7b2e9c4a6f10
Revises: d6f8a2c1b903
Create Date: 2026-10-01
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7b2e9c4a6f10"
down_revision: Union[str, Sequence[str], None] = "d6f8a2c1b903"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PROFILE_CHECK = "profile IN ('auto', 'passive', 'footprint', 'investigate', 'all')"


def upgrade() -> None:
    op.add_column(
        "search_runs",
        sa.Column(
            "profile",
            sa.String(length=20),
            nullable=False,
            server_default="auto",
        ),
    )
    op.create_check_constraint(
        "ck_search_runs_profile",
        "search_runs",
        PROFILE_CHECK,
    )
    op.create_index("ix_search_runs_profile", "search_runs", ["profile"])

    op.add_column(
        "search_schedules",
        sa.Column(
            "profile",
            sa.String(length=20),
            nullable=False,
            server_default="passive",
        ),
    )
    op.create_check_constraint(
        "ck_search_schedules_profile",
        "search_schedules",
        PROFILE_CHECK,
    )
    op.create_index(
        "ix_search_schedules_profile",
        "search_schedules",
        ["profile"],
    )


def downgrade() -> None:
    op.drop_index("ix_search_schedules_profile", table_name="search_schedules")
    op.drop_constraint(
        "ck_search_schedules_profile",
        "search_schedules",
        type_="check",
    )
    op.drop_column("search_schedules", "profile")

    op.drop_index("ix_search_runs_profile", table_name="search_runs")
    op.drop_constraint(
        "ck_search_runs_profile",
        "search_runs",
        type_="check",
    )
    op.drop_column("search_runs", "profile")
