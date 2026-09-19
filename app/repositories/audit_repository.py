from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.repositories.base_repository import BaseRepository


class AuditRepository(BaseRepository[AuditEvent]):
    def __init__(self, db: Session):
        super().__init__(AuditEvent, db)

    def last_event_hash_for_update(self) -> str | None:
        if self.db.bind is not None and self.db.bind.dialect.name == "postgresql":
            self.db.execute(text("SELECT pg_advisory_xact_lock(74193201)"))
        return self.db.scalar(
            select(AuditEvent.event_hash)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )

    def list_ordered(self) -> list[AuditEvent]:
        return list(
            self.db.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())).all()
        )

    def list_for_resource(
        self, resource_type: str, resource_id: int | str
    ) -> list[AuditEvent]:
        return list(
            self.db.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.resource_type == resource_type,
                    AuditEvent.resource_id == str(resource_id),
                )
                .order_by(AuditEvent.id.asc())
            ).all()
        )
