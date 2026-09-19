import hashlib
import json
from datetime import datetime, timezone

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
        previous_hash = self.repository.last_event_hash_for_update()
        created_at = datetime.now(timezone.utc)
        event_data = data or {}
        event_hash = self._event_hash(
            previous_hash=previous_hash,
            actor_user_id=actor_user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            data=event_data,
            created_at=created_at,
        )
        return self.repository.create(
            AuditEvent(
                actor_user_id=actor_user_id,
                action=action,
                resource_type=resource_type,
                resource_id=str(resource_id),
                event_data=event_data,
                previous_hash=previous_hash,
                event_hash=event_hash,
                created_at=created_at,
                updated_at=created_at,
            )
        )

    def verify_chain(self) -> dict[str, int | bool | str | None]:
        previous_hash = None
        checked = 0
        for event in self.repository.list_ordered():
            expected = self._event_hash(
                previous_hash=previous_hash,
                actor_user_id=event.actor_user_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                data=event.event_data,
                created_at=event.created_at,
            )
            if event.previous_hash != previous_hash or event.event_hash != expected:
                return {"valid": False, "checked": checked, "invalid_event_id": event.id}
            previous_hash = event.event_hash
            checked += 1
        return {"valid": True, "checked": checked, "invalid_event_id": None}

    def list_resource_activity(
        self, resource_type: str, resource_id: int | str
    ) -> list[AuditEvent]:
        return self.repository.list_for_resource(resource_type, resource_id)

    @staticmethod
    def _event_hash(
        *,
        previous_hash: str | None,
        actor_user_id: int | None,
        action: str,
        resource_type: str,
        resource_id: str,
        data: dict,
        created_at: datetime,
    ) -> str:
        canonical = json.dumps(
            {
                "previous_hash": previous_hash,
                "actor_user_id": actor_user_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "data": data,
                "created_at": created_at.isoformat(),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
