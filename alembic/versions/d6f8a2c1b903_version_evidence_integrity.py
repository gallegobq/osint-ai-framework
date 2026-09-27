"""version evidence integrity metadata

Revision ID: d6f8a2c1b903
Revises: a91f0c2d4e76
Create Date: 2026-09-19
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d6f8a2c1b903"
down_revision: Union[str, Sequence[str], None] = "a91f0c2d4e76"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Constant defaults make this additive migration safe for existing rows and
    # for a rolling deployment in which an older API can still write v1 data.
    op.add_column(
        "evidence",
        sa.Column(
            "integrity_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "evidence",
        sa.Column(
            "integrity_key_id",
            sa.String(length=64),
            nullable=False,
            server_default="legacy-secret-key",
        ),
    )


def downgrade() -> None:
    op.drop_column("evidence", "integrity_key_id")
    op.drop_column("evidence", "integrity_version")
