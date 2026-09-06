from typing import Protocol


class JobDispatcher(Protocol):
    def enqueue_collection(self, job_id: int) -> None: ...

    def enqueue_analysis(self, job_id: int) -> None: ...

    def enqueue_search_run(self, run_id: int) -> None: ...


class CeleryJobDispatcher:
    def enqueue_collection(self, job_id: int) -> None:
        from app.workers.tasks import execute_collection_job

        execute_collection_job.delay(job_id)

    def enqueue_analysis(self, job_id: int) -> None:
        from app.workers.tasks import execute_analysis_job

        execute_analysis_job.delay(job_id)

    def enqueue_search_run(self, run_id: int) -> None:
        from app.workers.tasks import execute_search_run

        execute_search_run.delay(run_id)
