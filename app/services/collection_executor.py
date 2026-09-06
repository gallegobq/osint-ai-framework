from datetime import datetime, timezone

from app.core.container import build_audit_service, build_evidence_service
from app.core.exceptions import NotFoundException
from app.osint.registry import CollectorRegistry
from app.repositories.job_repository import CollectionJobRepository
from app.repositories.user_repository import UserRepository
from app.schemas.evidence import EvidenceCreate
from app.schemas.job import JobStatus
from app.services.engagement_policy import active_testing_status


class CollectionExecutor:
    def __init__(
        self,
        repository: CollectionJobRepository,
        user_repository: UserRepository,
        registry: CollectorRegistry,
    ):
        self.repository = repository
        self.users = user_repository
        self.registry = registry

    def execute(self, job_id: int) -> dict:
        job = self.repository.get_by_id(job_id)
        if job is None:
            raise NotFoundException("Collection job")
        if job.status == JobStatus.SUCCEEDED.value:
            return job.result_summary or {}

        job.status = JobStatus.RUNNING.value
        job.attempts += 1
        job.started_at = datetime.now(timezone.utc)
        job.completed_at = None
        job.error = None
        self.repository.commit()

        try:
            actor = self.users.get_by_id(job.requested_by_id)
            if actor is None or not actor.is_active:
                raise RuntimeError("Requesting user is no longer active.")

            collector = self.registry.get(job.collector)
            if not collector.passive:
                active_allowed, reason = active_testing_status(job.investigation)
                search_policy = job.search_run.policy if job.search_run else {}
                if (
                    not active_allowed
                    or not job.search_run
                    or not job.search_run.allow_active
                    or not search_policy.get("authorization_confirmed")
                    or len((search_policy.get("scope_note") or "").strip()) < 10
                ):
                    raise RuntimeError(
                        reason or "Active collector authorization is invalid."
                    )
                normalized_query = collector.validate_query(job.query)
                authorized_values = {
                    str(target.get("value", "")).lower()
                    for target in job.search_run.targets
                }
                if any(
                    str(value).lower() not in authorized_values
                    for value in normalized_query.values()
                ):
                    raise RuntimeError(
                        "Active collector query no longer matches an authorized target."
                    )
            items = collector.collect(job.query)
            evidence_service = build_evidence_service(self.repository.db)
            evidence_ids = []

            for item in items:
                evidence = evidence_service.add(
                    actor,
                    job.investigation_id,
                    EvidenceCreate(
                        collector=collector.name,
                        source_type=item.source_type,
                        locator=item.locator,
                        source_metadata=item.source_metadata,
                        kind=item.kind,
                        title=item.title,
                        content=item.content,
                        observed_at=item.observed_at,
                        raw_data=item.raw_data,
                    ),
                    commit=False,
                )
                evidence_ids.append(evidence.id)

            result = {
                "items_collected": len(items),
                "evidence_ids": evidence_ids,
            }
            job.status = JobStatus.SUCCEEDED.value
            job.result_summary = result
            job.completed_at = datetime.now(timezone.utc)
            build_audit_service(self.repository.db).record(
                actor_user_id=actor.id,
                action="collection.succeeded",
                resource_type="collection_job",
                resource_id=job.id,
                data=result,
            )
            self.repository.commit()
            return result
        except Exception as exc:
            self.repository.rollback()
            failed_job = self.repository.get_by_id(job_id)
            if failed_job is not None:
                failed_job.status = JobStatus.FAILED.value
                failed_job.error = (
                    "Collection execution failed "
                    f"({type(exc).__name__})."
                )
                failed_job.completed_at = datetime.now(timezone.utc)
                build_audit_service(self.repository.db).record(
                    actor_user_id=failed_job.requested_by_id,
                    action="collection.failed",
                    resource_type="collection_job",
                    resource_id=failed_job.id,
                )
                self.repository.commit()
            raise RuntimeError("Collection job execution failed.") from None
