from sqlalchemy import ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base_model import BaseModel


class AuditEvent(BaseModel):
    __tablename__ = "audit_events"

    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    resource_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    event_data: Mapped[dict] = mapped_column(
        "data", JSON, nullable=False, default=dict
    )

    actor = relationship("User")
