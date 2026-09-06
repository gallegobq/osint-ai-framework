from datetime import datetime, timezone

from app.core.container import build_audit_service
from app.core.exceptions import NotFoundException
from app.models.job import CollectionJob
from app.osint.planner import SearchPlanner
from app.osint.registry import CollectorRegistry
from app.repositories.job_repository import (
    CollectionJobRepository,
    SearchRunRepository,
)
from app.repositories.user_repository import UserRepository
from app.schemas.job import JobStatus
from app.schemas.orchestration import SearchRunStatus
from app.services.collection_executor import CollectionExecutor
from app.services.engagement_policy import active_target_scope_status


class OrchestrationExecutor:
    def __init__(
        self,
        repository: SearchRunRepository,
        collection_repository: CollectionJobRepository,
        user_repository: UserRepository,
        registry: CollectorRegistry,
        planner: SearchPlanner,
    ):
        self.repository = repository
        self.collections = collection_repository
        self.users = user_repository
        self.registry = registry
        self.planner = planner

    def execute(self, run_id: int) -> dict:
        run = self.repository.get_by_id(run_id)
        if run is None:
            raise NotFoundException("Search run")
        if run.status in {
            SearchRunStatus.SUCCEEDED.value,
            SearchRunStatus.PARTIAL.value,
        }:
            return run.result_summary or {}

        run.status = SearchRunStatus.RUNNING.value
        run.started_at = datetime.now(timezone.utc)
        run.completed_at = None
        run.error = None
        self.repository.commit()

        try:
            actor = self.users.get_by_id(run.requested_by_id)
            if actor is None or not actor.is_active:
                raise RuntimeError("Requesting user is no longer active.")

            effective_allow_active = False
            if run.allow_active:
                effective_allow_active, reason = active_target_scope_status(
                    run.investigation,
                    run.targets,
                    (run.policy or {}).get("scope_note"),
                )
                if not effective_allow_active:
                    raise RuntimeError(
                        reason or "Active-testing authorization is no longer valid."
                    )

            plan = self.planner.plan(
                objective=run.objective,
                targets=run.targets,
                max_tools=run.max_tools,
                allow_active=effective_allow_active,
                operation_mode=run.investigation.operation_mode,
            )
            run.planner = plan.planner
            run.plan = {"summary": plan.summary, "steps": plan.steps}
            self.repository.commit()

            succeeded = 0
            failed = 0
            child_ids: list[int] = []
            evidence_ids: set[int] = set()
            for step in plan.steps:
                collector = self.registry.get(step["collector"])
                normalized_query = collector.validate_query(step["query"])
                child = self.collections.create(
                    CollectionJob(
                        investigation_id=run.investigation_id,
                        requested_by_id=run.requested_by_id,
                        search_run_id=run.id,
                        collector=collector.name,
                        query=normalized_query,
                        status=JobStatus.QUEUED.value,
                        attempts=0,
                    )
                )
                build_audit_service(self.repository.db).record(
                    actor_user_id=actor.id,
                    action="collection.enqueue",
                    resource_type="collection_job",
                    resource_id=child.id,
                    data={"collector": collector.name, "search_run_id": run.id},
                )
                self.collections.commit()
                child_ids.append(child.id)
                try:
                    result = CollectionExecutor(
                        repository=self.collections,
                        user_repository=self.users,
                        registry=self.registry,
                    ).execute(child.id)
                    succeeded += 1
                    evidence_ids.update(result.get("evidence_ids", []))
                except RuntimeError:
                    failed += 1

            result = {
                "planned_tools": len(plan.steps),
                "succeeded_tools": succeeded,
                "failed_tools": failed,
                "collection_job_ids": child_ids,
                "evidence_ids": sorted(evidence_ids),
                "human_review_required": True,
            }
            run = self.repository.get_by_id(run_id)
            if run is None:
                raise RuntimeError("Search run disappeared during execution.")
            if succeeded and failed:
                run.status = SearchRunStatus.PARTIAL.value
            elif succeeded:
                run.status = SearchRunStatus.SUCCEEDED.value
            else:
                run.status = SearchRunStatus.FAILED.value
                run.error = "All planned collectors failed."
            run.result_summary = result
            run.completed_at = datetime.now(timezone.utc)
            build_audit_service(self.repository.db).record(
                actor_user_id=actor.id,
                action=f"orchestration.{run.status}",
                resource_type="search_run",
                resource_id=run.id,
                data=result,
            )
            self.repository.commit()
            return result
        except Exception as exc:
            self.repository.rollback()
            failed_run = self.repository.get_by_id(run_id)
            if failed_run is not None:
                failed_run.status = SearchRunStatus.FAILED.value
                failed_run.error = (
                    "Search orchestration failed " f"({type(exc).__name__})."
                )
                failed_run.completed_at = datetime.now(timezone.utc)
                build_audit_service(self.repository.db).record(
                    actor_user_id=failed_run.requested_by_id,
                    action="orchestration.failed",
                    resource_type="search_run",
                    resource_id=failed_run.id,
                )
                self.repository.commit()
            raise RuntimeError("Search orchestration failed.") from None
