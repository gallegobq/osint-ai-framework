from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.core.exceptions import BadRequestException
from app.osint.contracts import Collector
from app.osint.registry import CollectorRegistry
from app.schemas.investigation import InvestigationCreate, InvestigationMode
from app.schemas.job import CollectionJobCreate
from app.schemas.orchestration import SearchRunCreate
from app.services.collection_service import CollectionService
from app.services.engagement_policy import active_testing_status
from app.services.engagement_policy import active_target_scope_status
from app.services.orchestration_service import OrchestrationService


class ActiveTestCollector(Collector):
    name = "test_active_probe"
    description = "Synthetic active collector used only for policy tests."
    target_types = frozenset({"domain"})
    query_field = "domain"
    passive = False

    def validate_query(self, query: dict) -> dict:
        return {"domain": str(query["domain"])}

    def collect(self, query: dict) -> list:
        return []


def test_investigations_default_to_passive_attack_surface_mode() -> None:
    data = InvestigationCreate(title="External footprint")

    assert data.operation_mode == InvestigationMode.ATTACK_SURFACE
    assert data.active_testing_authorized is False


@pytest.mark.parametrize(
    "payload",
    [
        {"operation_mode": "pentest"},
        {
            "operation_mode": "pentest",
            "authorization_scope": "Authorized systems and exclusions.",
            "active_testing_authorized": True,
        },
        {
            "operation_mode": "incident_response",
            "active_testing_authorized": True,
        },
    ],
)
def test_invalid_or_incomplete_pentest_policy_is_rejected(payload: dict) -> None:
    with pytest.raises(ValidationError):
        InvestigationCreate(title="Security engagement", **payload)


def test_complete_pentest_policy_is_accepted() -> None:
    now = datetime.now(timezone.utc)
    data = InvestigationCreate(
        title="Authorized web assessment",
        operation_mode="pentest",
        authorization_scope="Only example.com and its documented test environment.",
        active_testing_authorized=True,
        engagement_start_at=now - timedelta(minutes=5),
        engagement_end_at=now + timedelta(hours=1),
    )

    assert data.operation_mode == InvestigationMode.PENTEST
    assert data.authorization_scope.startswith("Only example.com")


def test_active_testing_status_rechecks_mode_authorization_and_window() -> None:
    now = datetime.now(timezone.utc)
    valid = SimpleNamespace(
        operation_mode="pentest",
        active_testing_authorized=True,
        authorization_scope="Authorized target: example.com",
        engagement_start_at=now - timedelta(minutes=1),
        engagement_end_at=now + timedelta(minutes=1),
    )
    expired = SimpleNamespace(
        **{
            **vars(valid),
            "engagement_end_at": now - timedelta(seconds=1),
        }
    )

    assert active_testing_status(valid, at=now) == (True, None)
    assert active_testing_status(expired, at=now)[0] is False
    valid.operation_mode = "incident_response"
    assert active_testing_status(valid, at=now)[0] is False


def test_active_targets_must_be_explicit_in_both_scope_records() -> None:
    now = datetime.now(timezone.utc)
    investigation = SimpleNamespace(
        operation_mode="pentest",
        active_testing_authorized=True,
        authorization_scope="Only example.com on TCP/443.",
        engagement_start_at=now - timedelta(minutes=1),
        engagement_end_at=now + timedelta(minutes=10),
    )
    targets = [{"type": "domain", "value": "example.com"}]

    assert active_target_scope_status(
        investigation,
        targets,
        "Validate TLS for example.com only.",
    ) == (True, None)
    assert active_target_scope_status(
        investigation,
        targets,
        "Validate TLS for another.example only.",
    )[0] is False


def test_orchestration_rejects_active_run_outside_pentest_mode() -> None:
    investigation = SimpleNamespace(
        operation_mode="attack_surface",
        active_testing_authorized=False,
        authorization_scope=None,
        engagement_start_at=None,
        engagement_end_at=None,
    )
    investigations = Mock()
    investigations.get_model.return_value = investigation
    service = OrchestrationService(
        repository=Mock(),
        investigations=investigations,
        audit_service=Mock(),
        dispatcher=Mock(),
    )
    request = SearchRunCreate(
        objective="Run authorized validation for example.com",
        targets=[{"type": "domain", "value": "example.com"}],
        max_tools=1,
        allow_active=True,
        authorization_confirmed=True,
        scope_note="Target-specific approved scope.",
    )

    with pytest.raises(BadRequestException):
        service.create(Mock(), 7, request)

    service.repository.create.assert_not_called()


def test_direct_collection_route_cannot_bypass_active_pentest_policy() -> None:
    investigations = Mock()
    registry = CollectorRegistry([ActiveTestCollector()])
    service = CollectionService(
        repository=Mock(),
        investigations=investigations,
        audit_service=Mock(),
        registry=registry,
        dispatcher=Mock(),
    )

    with pytest.raises(BadRequestException):
        service.create(
            Mock(id=3),
            9,
            CollectionJobCreate(
                collector="test_active_probe",
                query={"domain": "example.com"},
            ),
        )

    service.repository.create.assert_not_called()
