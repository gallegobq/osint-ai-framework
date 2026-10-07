from datetime import datetime, timezone

from app.core.container import build_audit_service
from app.core.exceptions import NotFoundException
from app.models.job import CollectionJob
from app.osint.planner import SearchPlanner
from app.osint.registry import CollectorRegistry
from app.repositories.job_repository import (
    CollectionJobRepository,
    SearchDiscoveryRepository,
    SearchRunRepository,
)
from app.repositories.user_repository import UserRepository
from app.schemas.job import JobStatus
from app.schemas.orchestration import SearchRunStatus
from app.services.collection_executor import CollectionExecutor
from app.services.engagement_policy import active_target_scope_status, require_active_actor


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
        self.discoveries = SearchDiscoveryRepository(repository.db)
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
        if not self.repository.claim(run_id, datetime.now(timezone.utc)):
            current = self.repository.get_by_id(run_id)
            return (current.result_summary or {"status": current.status, "duplicate": True})
        run = self.repository.get_by_id(run_id)
        if run is None:
            raise NotFoundException("Search run")

        try:
            actor = self.users.get_by_id(run.requested_by_id)
            if actor is None or not actor.is_active:
                raise RuntimeError("Requesting user is no longer active.")

            effective_allow_active = False
            if run.allow_active:
                require_active_actor(actor, self.users)
                effective_allow_active, reason = active_target_scope_status(
                    run.investigation,
                    run.targets,
                    (run.policy or {}).get("scope_note"),
                )
                if not effective_allow_active:
                    raise RuntimeError(
                        reason or "Active-testing authorization is no longer valid."
                    )

            initial_budget = run.max_tools
            if run.follow_discoveries and run.max_tools > 1:
                reserved = min(
                    run.discovery_max_depth,
                    run.max_tools - 1,
                )
                initial_budget -= reserved

            plan = self.planner.plan(
                objective=run.objective,
                targets=run.targets,
                max_tools=run.max_tools,
                allow_active=effective_allow_active,
                operation_mode=run.investigation.operation_mode,
                profile=run.profile,
            )
            seed_nodes = []
            for target in run.targets:
                node, _, _ = self.discoveries.get_or_create(
                    search_run_id=run.id,
                    target_type=target["type"],
                    target_value=target["value"],
                    depth=0,
                )
                self.discoveries.add_edge(
                    search_run_id=run.id,
                    parent_discovery_id=None,
                    child_discovery_id=node.id,
                    collection_job_id=None,
                    evidence_id=None,
                    relation="seed",
                    depth=0,
                )
                seed_nodes.append(node)

            initial_steps = (
                plan.steps[:initial_budget]
                if run.follow_discoveries
                else plan.steps
            )
            deferred_initial_steps = plan.steps[len(initial_steps) :]
            pending = [
                {
                    "step": step,
                    "node": seed_nodes[step["target_index"]],
                    "depth": 0,
                }
                for step in initial_steps
            ]
            run.planner = plan.planner
            run.plan = {
                "summary": plan.summary,
                "steps": [
                    {
                        **item["step"],
                        "depth": 0,
                        "input_discovery_id": item["node"].id,
                    }
                    for item in pending
                ],
                "discovery": {
                    "enabled": run.follow_discoveries,
                    "max_depth": run.discovery_max_depth,
                    "max_events": run.discovery_max_events,
                    "active_collectors": False,
                },
            }
            self.repository.commit()

            succeeded = 0
            failed = 0
            child_ids: list[int] = []
            evidence_ids: set[int] = set()
            executed_steps: list[dict] = []
            discovery_events = 0
            followed_discovery_jobs = 0
            discovery_truncated = False

            while pending and len(child_ids) < run.max_tools:
                next_nodes = {}
                for work in pending:
                    if len(child_ids) >= run.max_tools:
                        break
                    step = work["step"]
                    input_node = work["node"]
                    depth = work["depth"]
                    collector = self.registry.get(step["collector"])
                    normalized_query = collector.validate_query(step["query"])
                    child = self.collections.create(
                        CollectionJob(
                            investigation_id=run.investigation_id,
                            requested_by_id=run.requested_by_id,
                            search_run_id=run.id,
                            input_discovery_id=input_node.id,
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
                        data={
                            "collector": collector.name,
                            "search_run_id": run.id,
                            "input_discovery_id": input_node.id,
                            "discovery_depth": depth,
                        },
                    )
                    self.collections.commit()
                    child_ids.append(child.id)
                    executed_steps.append(
                        {
                            **step,
                            "depth": depth,
                            "input_discovery_id": input_node.id,
                            "target": {
                                "type": input_node.target_type,
                                "value": input_node.target_value,
                            },
                        }
                    )
                    if depth > 0:
                        followed_discovery_jobs += 1
                    try:
                        collection_result = CollectionExecutor(
                            repository=self.collections,
                            user_repository=self.users,
                            registry=self.registry,
                        ).execute(child.id)
                        succeeded += 1
                        evidence_ids.update(
                            collection_result.get("evidence_ids", [])
                        )
                    except RuntimeError:
                        failed += 1
                        continue

                    emitted = collection_result.get("discoveries", [])
                    for event in emitted:
                        if discovery_events >= run.discovery_max_events:
                            discovery_truncated = True
                            break
                        child_depth = depth + 1
                        (
                            discovered_node,
                            created,
                            depth_lowered,
                        ) = self.discoveries.get_or_create(
                            search_run_id=run.id,
                            target_type=event["target_type"],
                            target_value=event["target_value"],
                            depth=child_depth,
                        )
                        _, edge_created = self.discoveries.add_edge(
                            search_run_id=run.id,
                            parent_discovery_id=input_node.id,
                            child_discovery_id=discovered_node.id,
                            collection_job_id=child.id,
                            evidence_id=event["evidence_id"],
                            relation=event["relation"],
                            depth=child_depth,
                        )
                        if edge_created:
                            discovery_events += 1
                        if (
                            (created or depth_lowered)
                            and run.follow_discoveries
                            and child_depth <= run.discovery_max_depth
                        ):
                            next_nodes[discovered_node.id] = discovered_node
                remaining_tools = run.max_tools - len(child_ids)
                if (
                    not run.follow_discoveries
                    or not next_nodes
                    or remaining_tools <= 0
                ):
                    if deferred_initial_steps and remaining_tools > 0:
                        selected = deferred_initial_steps[:remaining_tools]
                        deferred_initial_steps = deferred_initial_steps[
                            len(selected) :
                        ]
                        pending = [
                            {
                                "step": step,
                                "node": seed_nodes[step["target_index"]],
                                "depth": 0,
                            }
                            for step in selected
                        ]
                        continue
                    break
                discovered_targets = [
                    {
                        "type": node.target_type,
                        "value": node.target_value,
                    }
                    for node in next_nodes.values()
                ]
                next_depth = min(
                    node.min_depth for node in next_nodes.values()
                )
                later_layers = max(
                    run.discovery_max_depth - next_depth,
                    0,
                )
                layer_budget = max(1, remaining_tools - later_layers)
                try:
                    derived_plan = self.planner.plan_discoveries(
                        targets=discovered_targets,
                        max_tools=min(layer_budget, remaining_tools),
                        profile=run.profile,
                    )
                except RuntimeError:
                    if deferred_initial_steps:
                        selected = deferred_initial_steps[:remaining_tools]
                        deferred_initial_steps = deferred_initial_steps[
                            len(selected) :
                        ]
                        pending = [
                            {
                                "step": step,
                                "node": seed_nodes[step["target_index"]],
                                "depth": 0,
                            }
                            for step in selected
                        ]
                        continue
                    break
                nodes = list(next_nodes.values())
                pending = [
                    {
                        "step": step,
                        "node": nodes[step["target_index"]],
                        "depth": nodes[step["target_index"]].min_depth,
                    }
                    for step in derived_plan.steps
                ]

            graph_nodes = self.discoveries.list_nodes(run.id)
            graph_edges = self.discoveries.list_edges(run.id)

            result = {
                "planned_tools": len(executed_steps),
                "initial_planned_tools": len(plan.steps),
                "succeeded_tools": succeeded,
                "failed_tools": failed,
                "collection_job_ids": child_ids,
                "evidence_ids": sorted(evidence_ids),
                "discovery_nodes": len(graph_nodes),
                "discovery_edges": len(graph_edges),
                "discovery_events_recorded": discovery_events,
                "followed_discovery_jobs": followed_discovery_jobs,
                "max_discovery_depth_reached": max(
                    (node.min_depth for node in graph_nodes),
                    default=0,
                ),
                "discovery_truncated": discovery_truncated,
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
            run.plan = {
                "summary": plan.summary,
                "steps": executed_steps,
                "discovery": {
                    "enabled": run.follow_discoveries,
                    "max_depth": run.discovery_max_depth,
                    "max_events": run.discovery_max_events,
                    "active_collectors": False,
                },
            }
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
