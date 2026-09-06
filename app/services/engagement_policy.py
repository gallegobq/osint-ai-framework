from datetime import datetime, timezone

from app.models.investigation import Investigation
from app.schemas.investigation import InvestigationMode


def active_testing_status(
    investigation: Investigation,
    *,
    at: datetime | None = None,
) -> tuple[bool, str | None]:
    """Evaluate the persisted rules of engagement at execution time."""

    if investigation.operation_mode != InvestigationMode.PENTEST.value:
        return False, "Active tools are only available in pentest mode."
    if not investigation.active_testing_authorized:
        return False, "Active testing is not authorized for this engagement."
    if not (investigation.authorization_scope or "").strip():
        return False, "The pentest authorization scope is missing."
    if (
        investigation.engagement_start_at is None
        or investigation.engagement_end_at is None
    ):
        return False, "The pentest engagement window is incomplete."

    current = at or datetime.now(timezone.utc)
    if current < investigation.engagement_start_at:
        return False, "The pentest engagement window has not started."
    if current > investigation.engagement_end_at:
        return False, "The pentest engagement window has ended."
    return True, None


def active_target_scope_status(
    investigation: Investigation,
    targets: list[dict],
    scope_note: str | None,
) -> tuple[bool, str | None]:
    """Require every currently supported active target in both scope records."""

    allowed, reason = active_testing_status(investigation)
    if not allowed:
        return False, reason
    active_targets = [
        str(target.get("value", "")).strip().lower()
        for target in targets
        if target.get("type") in {"domain", "hostname"}
    ]
    if not active_targets:
        return False, "Active validation requires an explicit domain or hostname."
    engagement_scope = (investigation.authorization_scope or "").lower()
    execution_scope = (scope_note or "").lower()
    for target in active_targets:
        if target not in engagement_scope or target not in execution_scope:
            return (
                False,
                "Every active target must appear explicitly in both the engagement "
                "scope and the execution scope note.",
            )
    return True, None
