from datetime import datetime, timezone

from app.core.exceptions import BadRequestException, NotFoundException
from app.core.exceptions import ServiceUnavailableException
from app.core.settings import settings
from app.models.job import SearchRun
from app.models.user import User
from app.osint.targets import infer_targets, normalize_target
from app.repositories.job_repository import SearchRunRepository
from app.schemas.orchestration import (
    SearchRunCreate,
    SearchRunRead,
    SearchRunStatus,
)
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.engagement_policy import active_target_scope_status
from app.services.investigation_service import InvestigationService
from app.workers.dispatcher import JobDispatcher


class OrchestrationService:
    def __init__(
        self,
        repository: SearchRunRepository,
        investigations: InvestigationService,
        audit_service: AuditService,
        dispatcher: JobDispatcher,
    ):
        self.repository = repository
        self.investigations = investigations
        self.audit = audit_service
        self.dispatcher = dispatcher

    def create(
        self,
        actor: User,
        investigation_id: int,
        data: SearchRunCreate,
    ) -> SearchRunRead:
        investigation = self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        if data.max_tools > settings.orchestrator_max_tools:
            raise BadRequestException(
                "max_tools exceeds the configured orchestration limit."
            )
        targets = (
            [
                {
                    "type": target.type.value,
                    "value": normalize_target(target.type.value, target.value),
                }
                for target in data.targets
            ]
            if data.targets
            else infer_targets(data.objective)
        )
        if data.allow_active:
            if len((data.scope_note or "").strip()) < 10:
                raise BadRequestException(
                    "Active pentest runs require a target-specific scope note."
                )
            active_allowed, reason = active_target_scope_status(
                investigation,
                targets,
                data.scope_note,
            )
            if not active_allowed:
                raise BadRequestException(reason or "Active testing is not allowed.")
        run = self.repository.create(
            SearchRun(
                investigation_id=investigation_id,
                requested_by_id=actor.id,
                objective=" ".join(data.objective.split()),
                targets=targets,
                max_tools=data.max_tools,
                allow_active=data.allow_active,
                policy={
                    "authorization_confirmed": True,
                    "scope_note": data.scope_note,
                    "allow_active": data.allow_active,
                    "execution_boundary": (
                        "soc-sandbox" if data.allow_active else "passive-collectors"
                    ),
                    "operation_mode": investigation.operation_mode,
                    "active_testing_authorized": (
                        investigation.active_testing_authorized
                    ),
                    "engagement_start_at": (
                        investigation.engagement_start_at.isoformat()
                        if investigation.engagement_start_at
                        else None
                    ),
                    "engagement_end_at": (
                        investigation.engagement_end_at.isoformat()
                        if investigation.engagement_end_at
                        else None
                    ),
                },
                status=SearchRunStatus.QUEUED.value,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="orchestration.enqueue",
            resource_type="search_run",
            resource_id=run.id,
            data={
                "target_types": sorted({item["type"] for item in targets}),
                "max_tools": data.max_tools,
                "allow_active": data.allow_active,
                "operation_mode": investigation.operation_mode,
            },
        )
        self.repository.commit()

        try:
            self.dispatcher.enqueue_search_run(run.id)
        except Exception as exc:
            run.status = SearchRunStatus.FAILED.value
            run.error = "Background queue unavailable."
            run.completed_at = datetime.now(timezone.utc)
            self.repository.commit()
            raise ServiceUnavailableException(
                "Background queue unavailable."
            ) from exc

        return SearchRunRead.model_validate(run)

    def get(self, actor: User, run_id: int) -> SearchRunRead:
        run = self.repository.get_by_id(run_id)
        if run is None:
            raise NotFoundException("Search run")
        self.investigations.get_model(actor, run.investigation_id)
        return SearchRunRead.model_validate(run)

    def list(
        self,
        actor: User,
        investigation_id: int,
    ) -> list[SearchRunRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            SearchRunRead.model_validate(run)
            for run in self.repository.list_by_investigation(investigation_id)
        ]
