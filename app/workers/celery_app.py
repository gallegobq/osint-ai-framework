from celery import Celery

from app.core.settings import settings


celery_app = Celery(
    "osint_ai_framework",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_always_eager=settings.celery_task_always_eager,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=settings.celery_task_time_limit_seconds,
    task_soft_time_limit=max(15, settings.celery_task_time_limit_seconds - 15),
    broker_transport_options={
        "visibility_timeout": settings.celery_visibility_timeout_seconds,
    },
    beat_schedule={
        "enqueue-due-passive-searches": {
            "task": "osint.run_due_search_schedules",
            "schedule": 60.0,
        }
    },
)
