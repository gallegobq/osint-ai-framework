from starlette.responses import Response

from app.api.v1.auth import _clear_refresh_cookie, _set_refresh_cookie
from app.models.audit_event import AuditEvent
from app.services.audit_service import AuditService


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def last_event_hash_for_update(self) -> str | None:
        return self.events[-1].event_hash if self.events else None

    def create(self, event: AuditEvent) -> AuditEvent:
        event.id = len(self.events) + 1
        self.events.append(event)
        return event

    def list_ordered(self) -> list[AuditEvent]:
        return self.events


def test_refresh_cookie_is_http_only_and_strict() -> None:
    response = Response()

    _set_refresh_cookie(response, "refresh-secret")

    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/api/v1/auth" in cookie


def test_refresh_cookie_can_be_cleared() -> None:
    response = Response()

    _clear_refresh_cookie(response)

    cookie = response.headers["set-cookie"].lower()
    assert "max-age=0" in cookie


def test_audit_hash_chain_detects_tampering() -> None:
    repository = InMemoryAuditRepository()
    service = AuditService(repository)  # type: ignore[arg-type]
    service.record(
        actor_user_id=1,
        action="finding.create",
        resource_type="finding",
        resource_id=7,
        data={"severity": "high"},
    )
    service.record(
        actor_user_id=1,
        action="finding.update",
        resource_type="finding",
        resource_id=7,
        data={"status": "resolved"},
    )

    assert service.verify_chain() == {
        "valid": True,
        "checked": 2,
        "invalid_event_id": None,
    }

    repository.events[0].event_data["severity"] = "informational"
    result = service.verify_chain()
    assert result["valid"] is False
    assert result["invalid_event_id"] == 1
