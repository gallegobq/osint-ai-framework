from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import (
    build_evidence_service,
    build_investigation_service,
)
from app.dependencies.database import get_db
from app.repositories.job_repository import AnalysisJobRepository
from app.services.report_service import ReportService


def get_report_service(
    db: Annotated[Session, Depends(get_db)],
) -> ReportService:
    return ReportService(
        investigations=build_investigation_service(db),
        evidence=build_evidence_service(db),
        analysis_repository=AnalysisJobRepository(db),
    )
