from unittest.mock import Mock

import pytest

from app.core.exceptions import BadRequestException, ForbiddenException
from app.models.project import Project, ProjectMember
from app.models.user import User
from app.osint.domain import normalize_domain
from app.osint.registry import CollectorRegistry
from app.schemas.evidence import EvidenceCreate
from app.schemas.project import ProjectMemberRole
from app.services.evidence_service import EvidenceService
from app.services.project_service import ProjectService


def test_domain_normalization_supports_idna() -> None:
    assert normalize_domain("  EXAMPLE.COM. ") == "example.com"
    assert normalize_domain("münich.example") == "xn--mnich-kva.example"


@pytest.mark.parametrize(
    "value",
    ["localhost", "https://example.com", "127.0.0.1", "bad_domain.com"],
)
def test_domain_normalization_rejects_non_domains(value: str) -> None:
    with pytest.raises(BadRequestException):
        normalize_domain(value)


def test_registry_rejects_unknown_collector() -> None:
    with pytest.raises(BadRequestException):
        CollectorRegistry([]).get("unknown")


def test_evidence_hash_is_deterministic() -> None:
    data = EvidenceCreate(
        collector="manual",
        source_type="document",
        locator="urn:test:1",
        kind="note",
        title="Finding",
        content="Observed fact",
        raw_data={"b": 2, "a": 1},
    )
    assert EvidenceService._content_hash(data) == EvidenceService._content_hash(
        data
    )
    assert len(EvidenceService._content_hash(data)) == 64


def test_project_viewer_cannot_update() -> None:
    project_repository = Mock()
    project_repository.get_by_id.return_value = Project(
        id=10,
        name="Test",
        slug="test",
        owner_id=1,
        status="active",
    )
    member_repository = Mock()
    member_repository.get_assignment.return_value = ProjectMember(
        project_id=10,
        user_id=2,
        role=ProjectMemberRole.VIEWER.value,
    )
    service = ProjectService(
        project_repository,
        member_repository,
        Mock(),
        Mock(),
    )
    actor = User(id=2, username="viewer", is_superuser=False)

    with pytest.raises(ForbiddenException):
        service.get(
            actor,
            10,
            minimum_role=ProjectMemberRole.EDITOR,
        )
