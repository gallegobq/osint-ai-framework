from app.database.session import SessionLocal
from app.llm.prompt_service import PromptService
from app.osint.registry import CollectorRegistry
from app.osint.planner import SearchPlanner
from app.repositories.job_repository import (
    AnalysisJobRepository,
    CollectionJobRepository,
    SearchRunRepository,
)
from app.repositories.user_repository import UserRepository
from app.repositories.soc_repository import SearchScheduleRepository
from app.schemas.orchestration import SearchRunCreate
from app.services.analysis_executor import AnalysisExecutor
from app.services.collection_executor import CollectionExecutor
from app.services.orchestration_executor import OrchestrationExecutor
from app.workers.celery_app import celery_app
from app.workers.dispatcher import CeleryJobDispatcher
from app.core.container import build_audit_service, build_investigation_service
from app.services.orchestration_service import OrchestrationService
from datetime import datetime, timedelta, timezone


@celery_app.task(
    name="osint.execute_collection_job",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=2,
)
def execute_collection_job(job_id: int) -> dict:
    db = SessionLocal()
    try:
        return CollectionExecutor(
            repository=CollectionJobRepository(db),
            user_repository=UserRepository(db),
            registry=CollectorRegistry(),
        ).execute(job_id)
    finally:
        db.close()


@celery_app.task(name="osint.execute_search_run")
def execute_search_run(run_id: int) -> dict:
    db = SessionLocal()
    try:
        registry = CollectorRegistry()
        return OrchestrationExecutor(
            repository=SearchRunRepository(db),
            collection_repository=CollectionJobRepository(db),
            user_repository=UserRepository(db),
            registry=registry,
            planner=SearchPlanner(registry),
        ).execute(run_id)
    finally:
        db.close()


@celery_app.task(
    name="osint.execute_analysis_job",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=1,
)
def execute_analysis_job(job_id: int) -> dict:
    db = SessionLocal()
    try:
        return AnalysisExecutor(
            repository=AnalysisJobRepository(db),
            user_repository=UserRepository(db),
            prompt_service=PromptService(),
        ).execute(job_id)
    finally:
        db.close()


@celery_app.task(name="osint.run_due_search_schedules")
def run_due_search_schedules() -> dict:
    """Enqueue authorized passive searches whose recurring schedule is due."""

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    processed = 0
    failed = 0
    try:
        schedules = SearchScheduleRepository(db)
        users = UserRepository(db)
        due = schedules.list_due(now)
        orchestration = OrchestrationService(
            repository=SearchRunRepository(db),
            investigations=build_investigation_service(db),
            audit_service=build_audit_service(db),
            dispatcher=CeleryJobDispatcher(),
        )
        for current in due:
            schedule_id = current.id
            try:
                actor = users.get_by_id(current.created_by_id)
                if actor is None or not actor.is_active:
                    current.enabled = False
                    current.last_error = "Schedule owner is not active."
                    schedules.commit()
                    failed += 1
                    continue
                run = orchestration.create(
                    actor,
                    current.investigation_id,
                    SearchRunCreate(
                        objective=current.objective,
                        targets=current.targets,
                        max_tools=current.max_tools,
                        allow_active=False,
                        authorization_confirmed=True,
                        scope_note=current.authorization_scope,
                    ),
                )
                current.last_run_at = now
                current.last_search_run_id = run.id
                current.last_error = None
                current.next_run_at = now + timedelta(
                    minutes=current.interval_minutes
                )
                schedules.commit()
                processed += 1
            except Exception as exc:
                db.rollback()
                current = schedules.get_by_id(schedule_id)
                if current is not None:
                    current.last_error = str(exc)[:1000]
                    current.next_run_at = now + timedelta(
                        minutes=current.interval_minutes
                    )
                    schedules.commit()
                failed += 1
        return {"due": len(due), "enqueued": processed, "failed": failed}
    finally:
        db.close()
