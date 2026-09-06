from __future__ import annotations

from datetime import datetime, timezone

from app.core.exceptions import BadRequestException, NotFoundException
from app.core.exceptions import ServiceUnavailableException
from app.core.settings import settings
from app.models.job import AnalysisJob
from app.models.user import User
from app.repositories.job_repository import AnalysisJobRepository
from app.schemas.job import AnalysisJobCreate, AnalysisJobRead, JobStatus
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.evidence_service import EvidenceService
from app.services.investigation_service import InvestigationService
from app.workers.dispatcher import JobDispatcher


class AnalysisService:
    def __init__(
        self,
        repository: AnalysisJobRepository,
        investigations: InvestigationService,
        evidence: EvidenceService,
        audit_service: AuditService,
        dispatcher: JobDispatcher,
    ):
        self.repository = repository
        self.investigations = investigations
        self.evidence = evidence
        self.audit = audit_service
        self.dispatcher = dispatcher

    def create(
        self,
        actor: User,
        investigation_id: int,
        data: AnalysisJobCreate,
    ) -> AnalysisJobRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        if not self.evidence.list(actor, investigation_id):
            raise BadRequestException(
                "At least one evidence record is required for analysis."
            )

        job = self.repository.create(
            AnalysisJob(
                investigation_id=investigation_id,
                requested_by_id=actor.id,
                analysis_type=data.analysis_type.value,
                provider=settings.llm_provider,
                prompt_version="v1",
                status=JobStatus.QUEUED.value,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="analysis.enqueue",
            resource_type="analysis_job",
            resource_id=job.id,
            data={"analysis_type": data.analysis_type.value},
        )
        self.repository.commit()

        try:
            self.dispatcher.enqueue_analysis(job.id)
        except Exception as exc:
            job.status = JobStatus.FAILED.value
            job.error = "Background queue unavailable."
            job.completed_at = datetime.now(timezone.utc)
            self.repository.commit()
            raise ServiceUnavailableException(
                "Background queue unavailable."
            ) from exc

        return AnalysisJobRead.model_validate(job)

    def get(self, actor: User, job_id: int) -> AnalysisJobRead:
        job = self.repository.get_by_id(job_id)
        if job is None:
            raise NotFoundException("Analysis job")
        self.investigations.get_model(actor, job.investigation_id)
        return AnalysisJobRead.model_validate(job)

    def list(
        self,
        actor: User,
        investigation_id: int,
    ) -> list[AnalysisJobRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            AnalysisJobRead.model_validate(job)
            for job in self.repository.list_by_investigation(investigation_id)
        ]
