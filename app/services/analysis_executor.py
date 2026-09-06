from datetime import datetime, timezone

from app.core.container import build_audit_service, build_evidence_service
from app.core.exceptions import NotFoundException
from app.llm.factory import build_llm_provider
from app.llm.prompt_service import PromptService
from app.llm.result_validation import validate_analysis_result
from app.repositories.job_repository import AnalysisJobRepository
from app.repositories.user_repository import UserRepository
from app.schemas.job import AnalysisType, JobStatus


class AnalysisExecutor:
    def __init__(
        self,
        repository: AnalysisJobRepository,
        user_repository: UserRepository,
        prompt_service: PromptService,
    ):
        self.repository = repository
        self.users = user_repository
        self.prompts = prompt_service

    def execute(self, job_id: int) -> dict:
        job = self.repository.get_by_id(job_id)
        if job is None:
            raise NotFoundException("Analysis job")
        if job.status == JobStatus.SUCCEEDED.value:
            return job.result or {}

        job.status = JobStatus.RUNNING.value
        job.started_at = datetime.now(timezone.utc)
        job.completed_at = None
        job.error = None
        self.repository.commit()

        try:
            actor = self.users.get_by_id(job.requested_by_id)
            if actor is None or not actor.is_active:
                raise RuntimeError("Requesting user is no longer active.")

            evidence_service = build_evidence_service(self.repository.db)
            evidence = evidence_service.list(actor, job.investigation_id)
            analysis_type = AnalysisType(job.analysis_type)
            prompt = self.prompts.build(analysis_type, evidence)
            output = build_llm_provider().generate_json(prompt)
            evidence_ids = {item.id for item in evidence}
            validated_output = validate_analysis_result(
                analysis_type,
                output,
                evidence_ids,
            )
            result = {
                "analysis": validated_output,
                "evidence_ids": sorted(evidence_ids),
                "human_review_required": True,
            }

            job.status = JobStatus.SUCCEEDED.value
            job.result = result
            job.completed_at = datetime.now(timezone.utc)
            build_audit_service(self.repository.db).record(
                actor_user_id=actor.id,
                action="analysis.succeeded",
                resource_type="analysis_job",
                resource_id=job.id,
                data={"analysis_type": job.analysis_type},
            )
            self.repository.commit()
            return result
        except Exception as exc:
            self.repository.rollback()
            failed_job = self.repository.get_by_id(job_id)
            if failed_job is not None:
                failed_job.status = JobStatus.FAILED.value
                failed_job.error = (
                    "Analysis execution failed "
                    f"({type(exc).__name__})."
                )
                failed_job.completed_at = datetime.now(timezone.utc)
                build_audit_service(self.repository.db).record(
                    actor_user_id=failed_job.requested_by_id,
                    action="analysis.failed",
                    resource_type="analysis_job",
                    resource_id=failed_job.id,
                )
                self.repository.commit()
            raise RuntimeError("Analysis job execution failed.") from None
