from datetime import datetime, timezone

from app.schemas.evidence import EvidenceRead
from app.schemas.investigation import (
    InvestigationKind,
    InvestigationMode,
    InvestigationRead,
    InvestigationStatus,
    Priority,
)
from app.schemas.report import InvestigationReport
from app.services.report_service import ReportService


NOW = datetime(2026, 8, 16, 8, 0, tzinfo=timezone.utc)


def _investigation() -> InvestigationRead:
    return InvestigationRead(
        id=7,
        project_id=3,
        created_by_id=1,
        title="Authorized footprint review",
        description="Passive review of assets owned by the operator.",
        kind=InvestigationKind.MIXED,
        status=InvestigationStatus.ACTIVE,
        priority=Priority.MEDIUM,
        operation_mode=InvestigationMode.ATTACK_SURFACE,
        authorization_scope=None,
        active_testing_authorized=False,
        engagement_start_at=None,
        engagement_end_at=None,
        jurisdiction="Colombia",
        legal_basis="Authorized security assessment",
        data_classification="internal",
        retention_until=None,
        legal_hold=False,
        created_at=NOW,
        updated_at=NOW,
    )


def _evidence(
    evidence_id: int,
    source_id: int,
    kind: str,
    title: str,
) -> EvidenceRead:
    return EvidenceRead(
        id=evidence_id,
        investigation_id=7,
        source_id=source_id,
        created_by_id=1,
        kind=kind,
        title=title,
        content='{"public": true}',
        content_hash="a" * 64,
        observed_at=NOW,
        collected_at=NOW,
        raw_data={"public": True},
        created_at=NOW,
    )


def _report(evidence: list[EvidenceRead]) -> InvestigationReport:
    return InvestigationReport(
        generated_at=NOW,
        investigation=_investigation(),
        evidence=evidence,
        entities=[],
        relations=[],
        analyses=[],
        warnings=[
            "AI-assisted observations are hypotheses that require human review."
        ],
    )


def test_markdown_report_explains_public_exposure_in_plain_language() -> None:
    report = _report(
        [
            _evidence(11, 101, "dns_records", "DNS records for example.com"),
            _evidence(12, 102, "github_user", "GitHub public profile for owner"),
        ]
    )

    markdown = ReportService.render_markdown(ReportService.__new__(ReportService), report)

    assert "## Executive summary" in markdown
    assert "The search returned **2 evidence records**" in markdown
    assert "Publicly visible data was observed" in markdown
    assert "Domain and web infrastructure" in markdown
    assert "Public profiles and developer activity" in markdown
    assert "does **not** by itself prove a security vulnerability" in markdown
    assert "DNS records for example.com [E11]" in markdown
    assert "GitHub public profile for owner [E12]" in markdown
    assert "## Recommended next steps" in markdown
    assert "## Technical evidence appendix" in markdown
    assert "used no LLM tokens" in markdown


def test_markdown_report_does_not_overstate_an_empty_search() -> None:
    markdown = ReportService.render_markdown(
        ReportService.__new__(ReportService),
        _report([]),
    )

    assert "did not return evidence records" in markdown
    assert "does not prove that no public information exists" in markdown
    assert "No evidence-backed exposure surface" in markdown
