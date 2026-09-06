from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import build_audit_service, build_investigation_service
from app.dependencies.database import get_db
from app.repositories.job_repository import SearchRunRepository
from app.services.orchestration_service import OrchestrationService
from app.workers.dispatcher import CeleryJobDispatcher


def get_orchestration_service(
    db: Annotated[Session, Depends(get_db)],
) -> OrchestrationService:
    return OrchestrationService(
        repository=SearchRunRepository(db),
        investigations=build_investigation_service(db),
        audit_service=build_audit_service(db),
        dispatcher=CeleryJobDispatcher(),
    )
