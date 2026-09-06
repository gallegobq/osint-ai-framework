from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import (
    build_audit_service,
    build_evidence_service,
    build_investigation_service,
)
from app.dependencies.database import get_db
from app.repositories.job_repository import AnalysisJobRepository
from app.services.analysis_service import AnalysisService
from app.workers.dispatcher import CeleryJobDispatcher


def get_analysis_service(
    db: Annotated[Session, Depends(get_db)],
) -> AnalysisService:
    return AnalysisService(
        repository=AnalysisJobRepository(db),
        investigations=build_investigation_service(db),
        evidence=build_evidence_service(db),
        audit_service=build_audit_service(db),
        dispatcher=CeleryJobDispatcher(),
    )
