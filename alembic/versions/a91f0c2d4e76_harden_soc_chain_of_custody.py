"""harden SOC workflow and chain of custody

Revision ID: a91f0c2d4e76
Revises: e2a45f41c4b0
Create Date: 2026-09-17
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a91f0c2d4e76"
down_revision: Union[str, Sequence[str], None] = "e2a45f41c4b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _audit_hash(row: dict, previous_hash: str | None) -> str:
    canonical = json.dumps(
        {
            "previous_hash": previous_hash,
            "actor_user_id": row["actor_user_id"],
            "action": row["action"],
            "resource_type": row["resource_type"],
            "resource_id": str(row["resource_id"]),
            "data": row["data"] or {},
            "created_at": row["created_at"].isoformat(),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("previous_hash", sa.String(64)))
    op.add_column("audit_events", sa.Column("event_hash", sa.String(64)))
    op.add_column("evidence", sa.Column("integrity_signature", sa.String(64)))

    op.add_column("findings", sa.Column("assignee_id", sa.Integer()))
    op.add_column(
        "findings",
        sa.Column("mitre_tactics", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "findings",
        sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "findings",
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column("findings", sa.Column("resolution_summary", sa.Text()))
    op.add_column("findings", sa.Column("closure_reason", sa.Text()))
    op.create_foreign_key(
        "fk_findings_assignee_id_users",
        "findings",
        "users",
        ["assignee_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_findings_assignee_id", "findings", ["assignee_id"])

    bind = op.get_bind()
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY is required to sign existing evidence.")
    evidence_rows = bind.execute(
        sa.text("SELECT id, content_hash FROM evidence ORDER BY id")
    ).mappings()
    for row in evidence_rows:
        signature = hmac.new(
            secret.encode("utf-8"),
            row["content_hash"].encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        bind.execute(
            sa.text(
                "UPDATE evidence SET integrity_signature = :signature WHERE id = :id"
            ),
            {"signature": signature, "id": row["id"]},
        )

    previous_hash = None
    audit_rows = bind.execute(
        sa.text(
            "SELECT id, actor_user_id, action, resource_type, resource_id, "
            "data, created_at FROM audit_events ORDER BY id"
        )
    ).mappings()
    for row in audit_rows:
        event_hash = _audit_hash(dict(row), previous_hash)
        bind.execute(
            sa.text(
                "UPDATE audit_events SET previous_hash = :previous_hash, "
                "event_hash = :event_hash WHERE id = :id"
            ),
            {
                "previous_hash": previous_hash,
                "event_hash": event_hash,
                "id": row["id"],
            },
        )
        previous_hash = event_hash

    op.alter_column("audit_events", "event_hash", nullable=False)
    op.alter_column("evidence", "integrity_signature", nullable=False)
    op.create_index(
        "ix_audit_events_event_hash",
        "audit_events",
        ["event_hash"],
        unique=True,
    )
    op.create_index(
        "ix_evidence_integrity_signature",
        "evidence",
        ["integrity_signature"],
    )
    op.execute(
        "CREATE INDEX ix_knowledge_chunks_content_fts ON knowledge_chunks "
        "USING gin (to_tsvector('simple', content))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_knowledge_chunks_content_fts")
    op.drop_index("ix_evidence_integrity_signature", table_name="evidence")
    op.drop_index("ix_audit_events_event_hash", table_name="audit_events")
    op.drop_index("ix_findings_assignee_id", table_name="findings")
    op.drop_constraint(
        "fk_findings_assignee_id_users", "findings", type_="foreignkey"
    )
    for column in (
        "closure_reason",
        "resolution_summary",
        "tags",
        "mitre_techniques",
        "mitre_tactics",
        "assignee_id",
    ):
        op.drop_column("findings", column)
    op.drop_column("evidence", "integrity_signature")
    op.drop_column("audit_events", "event_hash")
    op.drop_column("audit_events", "previous_hash")
