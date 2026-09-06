from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.analysis import get_analysis_service
from app.models.user import User
from app.schemas.job import AnalysisJobCreate, AnalysisJobRead
from app.services.analysis_service import AnalysisService


router = APIRouter(tags=["Analysis"])


@router.post(
    "/investigations/{investigation_id}/analysis-jobs",
    response_model=AnalysisJobRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_analysis_job(
    investigation_id: int,
    data: AnalysisJobCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Analysis.EXECUTE)),
    ],
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
) -> AnalysisJobRead:
    return service.create(current_user, investigation_id, data)


@router.get(
    "/investigations/{investigation_id}/analysis-jobs",
    response_model=list[AnalysisJobRead],
)
def list_analysis_jobs(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Analysis.READ)),
    ],
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
) -> list[AnalysisJobRead]:
    return service.list(current_user, investigation_id)


@router.get("/analysis-jobs/{job_id}", response_model=AnalysisJobRead)
def get_analysis_job(
    job_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Analysis.READ)),
    ],
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
) -> AnalysisJobRead:
    return service.get(current_user, job_id)
