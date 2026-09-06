from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base_model import BaseModel


if TYPE_CHECKING:
    from app.models.project import Project


class Investigation(BaseModel):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('person', 'company', 'domain', 'mixed')",
            name="ck_investigations_kind",
        ),
        CheckConstraint(
            "status IN ('draft', 'active', 'paused', 'completed', 'archived')",
            name="ck_investigations_status",
        ),
        CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_investigations_priority",
        ),
        CheckConstraint(
            "operation_mode IN ('attack_surface', 'incident_response', 'pentest')",
            name="ck_investigations_operation_mode",
        ),
        CheckConstraint(
            "active_testing_authorized = false OR operation_mode = 'pentest'",
            name="ck_investigations_active_requires_pentest",
        ),
        CheckConstraint(
            "data_classification IN ('public', 'internal', 'confidential', 'restricted')",
            name="ck_investigations_data_classification",
        ),
        CheckConstraint(
            "(engagement_start_at IS NULL AND engagement_end_at IS NULL) OR "
            "(engagement_start_at IS NOT NULL AND engagement_end_at IS NOT NULL "
            "AND engagement_end_at > engagement_start_at)",
            name="ck_investigations_engagement_window",
        ),
    )

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str] = mapped_column(
        String(20), nullable=False, default="mixed", index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="draft", index=True
    )
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium", index=True
    )
    operation_mode: Mapped[str] = mapped_column(
        String(30), nullable=False, default="attack_surface", index=True
    )
    authorization_scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    active_testing_authorized: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    engagement_start_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    engagement_end_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    jurisdiction: Mapped[str | None] = mapped_column(String(100), nullable=True)
    legal_basis: Mapped[str | None] = mapped_column(Text, nullable=True)
    data_classification: Mapped[str] = mapped_column(
        String(20), nullable=False, default="internal", index=True
    )
    retention_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    project: Mapped["Project"] = relationship(
        "Project", back_populates="investigations"
    )
    created_by = relationship("User", foreign_keys=[created_by_id])
    tasks: Mapped[list["InvestigationTask"]] = relationship(
        "InvestigationTask",
        back_populates="investigation",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class InvestigationTask(BaseModel):
    __tablename__ = "investigation_tasks"
    __table_args__ = (
        CheckConstraint(
            "status IN ('todo', 'in_progress', 'blocked', 'done')",
            name="ck_investigation_tasks_status",
        ),
        CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_investigation_tasks_priority",
        ),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assignee_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="todo", index=True
    )
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium", index=True
    )
    due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    investigation: Mapped["Investigation"] = relationship(
        "Investigation", back_populates="tasks"
    )
    assignee = relationship("User", foreign_keys=[assignee_id])
