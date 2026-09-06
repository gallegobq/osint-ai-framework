"""add user lifecycle fields

Revision ID: bf122a96481a
Revises: 9de1d11f1f57
Create Date: 2026-07-26 20:12:32.040104

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "bf122a96481a"
down_revision: Union[str, Sequence[str], None] = "9de1d11f1f57"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Add lifecycle-management fields to the users table.

    password_changed_at records when the current password became valid.
    deleted_at implements soft deletion without physically removing users.
    """
    op.add_column(
        "users",
        sa.Column(
            "password_changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    op.add_column(
        "users",
        sa.Column(
            "deleted_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.create_index(
        op.f("ix_users_deleted_at"),
        "users",
        ["deleted_at"],
        unique=False,
    )


def downgrade() -> None:
    """
    Remove lifecycle-management fields from the users table.
    """
    op.drop_index(
        op.f("ix_users_deleted_at"),
        table_name="users",
    )

    op.drop_column(
        "users",
        "deleted_at",
    )

    op.drop_column(
        "users",
        "password_changed_at",
    )
