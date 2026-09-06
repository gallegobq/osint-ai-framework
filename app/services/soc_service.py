from datetime import datetime, timedelta, timezone

from app.core.exceptions import BadRequestException, NotFoundException
from app.core.settings import settings
from app.models.soc import Finding, SearchSchedule
from app.models.user import User
from app.osint.targets import normalize_target
from app.repositories.evidence_repository import EvidenceRepository
from app.repositories.soc_repository import (
    FindingRepository,
    SearchScheduleRepository,
)
from app.schemas.project import ProjectMemberRole
from app.schemas.soc import (
    FindingCreate,
    FindingRead,
    FindingStatus,
    FindingUpdate,
    SearchScheduleCreate,
    SearchScheduleRead,
    SearchScheduleUpdate,
)
from app.services.audit_service import AuditService
from app.services.investigation_service import InvestigationService


class SocService:
    def __init__(
        self,
        findings: FindingRepository,
        schedules: SearchScheduleRepository,
        evidence: EvidenceRepository,
        investigations: InvestigationService,
        audit: AuditService,
    ):
        self.findings = findings
        self.schedules = schedules
        self.evidence = evidence
        self.investigations = investigations
        self.audit = audit

    def create_finding(
        self, actor: User, investigation_id: int, data: FindingCreate
    ) -> FindingRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        if data.evidence_id is not None:
            evidence = self.evidence.get_by_id(data.evidence_id)
            if evidence is None or evidence.investigation_id != investigation_id:
                raise NotFoundException("Investigation evidence")
        finding = self.findings.create(
            Finding(
                investigation_id=investigation_id,
                evidence_id=data.evidence_id,
                created_by_id=actor.id,
                title=data.title,
                description=data.description,
                severity=data.severity.value,
                status=FindingStatus.OPEN.value,
                confidence=data.confidence,
                remediation=data.remediation,
                due_at=data.due_at,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="findings.create",
            resource_type="finding",
            resource_id=finding.id,
            data={"investigation_id": investigation_id, "severity": finding.severity},
        )
        self.findings.commit()
        return FindingRead.model_validate(finding)

    def list_findings(
        self, actor: User, investigation_id: int
    ) -> list[FindingRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            FindingRead.model_validate(item)
            for item in self.findings.list_by_investigation(investigation_id)
        ]

    def update_finding(
        self,
        actor: User,
        investigation_id: int,
        finding_id: int,
        data: FindingUpdate,
    ) -> FindingRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        finding = self.findings.get_by_id(finding_id)
        if finding is None or finding.investigation_id != investigation_id:
            raise NotFoundException("Investigation finding")
        values = data.model_dump(exclude_unset=True)
        for enum_field in ("severity", "status"):
            if values.get(enum_field) is not None:
                values[enum_field] = values[enum_field].value
        for field, value in values.items():
            setattr(finding, field, value)
        if finding.status in {
            FindingStatus.RESOLVED.value,
            FindingStatus.FALSE_POSITIVE.value,
        }:
            finding.resolved_at = finding.resolved_at or datetime.now(timezone.utc)
        else:
            finding.resolved_at = None
        self.audit.record(
            actor_user_id=actor.id,
            action="findings.update",
            resource_type="finding",
            resource_id=finding.id,
            data={"fields": sorted(data.model_fields_set)},
        )
        self.findings.commit()
        return FindingRead.model_validate(finding)

    def create_schedule(
        self, actor: User, investigation_id: int, data: SearchScheduleCreate
    ) -> SearchScheduleRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        if data.max_tools > settings.orchestrator_max_tools:
            raise BadRequestException(
                "max_tools exceeds the configured orchestration limit."
            )
        targets = [
            {
                "type": target.type.value,
                "value": normalize_target(target.type.value, target.value),
            }
            for target in data.targets
        ]
        now = datetime.now(timezone.utc)
        schedule = self.schedules.create(
            SearchSchedule(
                investigation_id=investigation_id,
                created_by_id=actor.id,
                name=data.name,
                objective=" ".join(data.objective.split()),
                targets=targets,
                max_tools=data.max_tools,
                interval_minutes=data.interval_minutes,
                authorization_scope=data.authorization_scope.strip(),
                enabled=data.enabled,
                next_run_at=now + timedelta(minutes=data.interval_minutes),
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="search_schedules.create",
            resource_type="search_schedule",
            resource_id=schedule.id,
            data={"investigation_id": investigation_id},
        )
        self.schedules.commit()
        return SearchScheduleRead.model_validate(schedule)

    def list_schedules(
        self, actor: User, investigation_id: int
    ) -> list[SearchScheduleRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            SearchScheduleRead.model_validate(item)
            for item in self.schedules.list_by_investigation(investigation_id)
        ]

    def update_schedule(
        self,
        actor: User,
        investigation_id: int,
        schedule_id: int,
        data: SearchScheduleUpdate,
    ) -> SearchScheduleRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        schedule = self.schedules.get_by_id(schedule_id)
        if schedule is None or schedule.investigation_id != investigation_id:
            raise NotFoundException("Search schedule")
        values = data.model_dump(exclude_unset=True)
        if values.get("max_tools", schedule.max_tools) > settings.orchestrator_max_tools:
            raise BadRequestException(
                "max_tools exceeds the configured orchestration limit."
            )
        if data.targets is not None:
            values["targets"] = [
                {
                    "type": target.type.value,
                    "value": normalize_target(target.type.value, target.value),
                }
                for target in data.targets
            ]
        if values.get("objective") is not None:
            values["objective"] = " ".join(values["objective"].split())
        if values.get("authorization_scope") is not None:
            values["authorization_scope"] = values["authorization_scope"].strip()
        for field, value in values.items():
            setattr(schedule, field, value)
        if "interval_minutes" in values or values.get("enabled") is True:
            schedule.next_run_at = datetime.now(timezone.utc) + timedelta(
                minutes=schedule.interval_minutes
            )
        self.audit.record(
            actor_user_id=actor.id,
            action="search_schedules.update",
            resource_type="search_schedule",
            resource_id=schedule.id,
            data={"fields": sorted(data.model_fields_set)},
        )
        self.schedules.commit()
        return SearchScheduleRead.model_validate(schedule)
