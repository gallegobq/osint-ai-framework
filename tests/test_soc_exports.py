from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

from app.models.user import User
from app.services.soc_export_service import SocExportService


def build_service() -> tuple[SocExportService, User]:
    now = datetime.now(timezone.utc)
    investigation = SimpleNamespace(
        id=3,
        title="Incident IOC review",
        description="Authorized incident response",
        operation_mode="incident_response",
        created_at=now,
        updated_at=now,
    )
    investigations = Mock()
    investigations.get_model.return_value = investigation
    entities = Mock()
    entities.list_by_investigation.return_value = [
        SimpleNamespace(
            id=4,
            entity_type="cve",
            canonical_name="CVE-2021-44228",
            created_at=now,
            updated_at=now,
        ),
        SimpleNamespace(
            id=5,
            entity_type="hash",
            canonical_name="a" * 64,
            created_at=now,
            updated_at=now,
        ),
    ]
    evidence = Mock()
    evidence.list_by_investigation.return_value = []
    findings = Mock()
    findings.list_by_investigation.return_value = [
        SimpleNamespace(
            id=7,
            evidence_id=None,
            title="Known exploited vulnerability",
            description="The exposed component requires urgent remediation.",
            severity="critical",
            status="open",
            confidence=Decimal("0.950"),
            remediation="Upgrade the affected component.",
            created_at=now,
            updated_at=now,
        )
    ]
    return (
        SocExportService(investigations, entities, evidence, findings),
        User(id=1, username="analyst"),
    )


def test_stix_export_contains_bundle_observables_and_finding() -> None:
    service, actor = build_service()
    bundle = service.build_stix(actor, 3)
    object_types = {item["type"] for item in bundle["objects"]}

    assert bundle["type"] == "bundle"
    assert {"vulnerability", "file", "note", "grouping"} <= object_types
    assert all(item.get("spec_version") == "2.1" for item in bundle["objects"])


def test_siem_exports_include_severity_and_status() -> None:
    service, actor = build_service()

    assert '"severity":"critical"' in service.build_ndjson(actor, 3)
    cef = service.build_cef(actor, 3)
    assert cef.startswith("CEF:0|OSINT AI Framework|")
    assert "cs2=open" in cef
