from app.models.audit_event import AuditEvent
from app.repositories.audit_repository import AuditRepository


class AuditService:
    def __init__(self, repository: AuditRepository):
        self.repository = repository

    def record(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        resource_type: str,
        resource_id: int | str,
        data: dict | None = None,
    ) -> AuditEvent:
        return self.repository.create(
            AuditEvent(
                actor_user_id=actor_user_id,
                action=action,
                resource_type=resource_type,
                resource_id=str(resource_id),
                event_data=data or {},
            )
        )
