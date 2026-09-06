from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.repositories.base_repository import BaseRepository


class AuditRepository(BaseRepository[AuditEvent]):
    def __init__(self, db: Session):
        super().__init__(AuditEvent, db)
