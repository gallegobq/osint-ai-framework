"""repair user sessions table

Revision ID: c71db15a2e0f
Revises: bf122a96481a
Create Date: 2026-08-15

The original 4cda165c53c7 revision was committed empty.  This forward-only
repair keeps already-applied databases upgradeable while also making clean
installations produce the schema represented by the ORM model.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c71db15a2e0f"
down_revision: Union[str, Sequence[str], None] = "bf122a96481a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    if "user_sessions" in sa.inspect(bind).get_table_names():
        return

    op.create_table(
        "user_sessions",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("jti", sa.String(length=36), nullable=False),
        sa.Column("access_jti", sa.String(length=36), nullable=False),
        sa.Column(
            "refresh_token_hash",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column("device_name", sa.String(length=100), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
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
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("jti"),
        sa.UniqueConstraint("access_jti"),
        sa.UniqueConstraint("refresh_token_hash"),
    )
    op.create_index(
        op.f("ix_user_sessions_id"),
        "user_sessions",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_sessions_user_id"),
        "user_sessions",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_sessions_jti"),
        "user_sessions",
        ["jti"],
        unique=True,
    )
    op.create_index(
        op.f("ix_user_sessions_access_jti"),
        "user_sessions",
        ["access_jti"],
        unique=True,
    )


def downgrade() -> None:
    bind = op.get_bind()

    if "user_sessions" not in sa.inspect(bind).get_table_names():
        return

    op.drop_index(
        op.f("ix_user_sessions_access_jti"),
        table_name="user_sessions",
    )
    op.drop_index(
        op.f("ix_user_sessions_jti"),
        table_name="user_sessions",
    )
    op.drop_index(
        op.f("ix_user_sessions_user_id"),
        table_name="user_sessions",
    )
    op.drop_index(
        op.f("ix_user_sessions_id"),
        table_name="user_sessions",
    )
    op.drop_table("user_sessions")
