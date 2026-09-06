from __future__ import annotations

from datetime import datetime, timezone

from app.core.exceptions import (
    BadRequestException,
    NotFoundException,
    ServiceUnavailableException,
)
from app.models.job import CollectionJob
from app.models.user import User
from app.osint.registry import CollectorRegistry
from app.repositories.job_repository import CollectionJobRepository
from app.schemas.job import CollectionJobCreate, CollectionJobRead, JobStatus
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.investigation_service import InvestigationService
from app.workers.dispatcher import JobDispatcher


class CollectionService:
    def __init__(
        self,
        repository: CollectionJobRepository,
        investigations: InvestigationService,
        audit_service: AuditService,
        registry: CollectorRegistry,
        dispatcher: JobDispatcher,
    ):
        self.repository = repository
        self.investigations = investigations
        self.audit = audit_service
        self.registry = registry
        self.dispatcher = dispatcher

    def available_collectors(self) -> list[dict[str, object]]:
        return self.registry.describe()

    def create(
        self,
        actor: User,
        investigation_id: int,
        data: CollectionJobCreate,
    ) -> CollectionJobRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        collector = self.registry.get(data.collector)
        if not collector.passive:
            raise BadRequestException(
                "Active collectors must be launched through an authorized "
                "pentest search run."
            )
        query = collector.validate_query(data.query)
        job = self.repository.create(
            CollectionJob(
                investigation_id=investigation_id,
                requested_by_id=actor.id,
                collector=collector.name,
                query=query,
                status=JobStatus.QUEUED.value,
                attempts=0,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="collection.enqueue",
            resource_type="collection_job",
            resource_id=job.id,
            data={"collector": collector.name},
        )
        self.repository.commit()

        try:
            self.dispatcher.enqueue_collection(job.id)
        except Exception as exc:
            job.status = JobStatus.FAILED.value
            job.error = "Background queue unavailable."
            job.completed_at = datetime.now(timezone.utc)
            self.repository.commit()
            raise ServiceUnavailableException(
                "Background queue unavailable."
            ) from exc

        return CollectionJobRead.model_validate(job)

    def get(
        self,
        actor: User,
        job_id: int,
    ) -> CollectionJobRead:
        job = self.repository.get_by_id(job_id)
        if job is None:
            raise NotFoundException("Collection job")
        self.investigations.get_model(actor, job.investigation_id)
        return CollectionJobRead.model_validate(job)

    def list(
        self,
        actor: User,
        investigation_id: int,
    ) -> list[CollectionJobRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            CollectionJobRead.model_validate(job)
            for job in self.repository.list_by_investigation(investigation_id)
        ]
