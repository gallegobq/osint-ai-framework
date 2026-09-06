from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.soc import get_soc_service
from app.models.user import User
from app.schemas.soc import (
    FindingCreate,
    FindingRead,
    FindingUpdate,
    SearchScheduleCreate,
    SearchScheduleRead,
    SearchScheduleUpdate,
)
from app.services.soc_service import SocService


router = APIRouter(prefix="/investigations", tags=["SOC Operations"])


@router.post(
    "/{investigation_id}/findings",
    response_model=FindingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    investigation_id: int,
    data: FindingCreate,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Findings.CREATE))
    ],
    service: Annotated[SocService, Depends(get_soc_service)],
) -> FindingRead:
    return service.create_finding(current_user, investigation_id, data)


@router.get("/{investigation_id}/findings", response_model=list[FindingRead])
def list_findings(
    investigation_id: int,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Findings.READ))
    ],
    service: Annotated[SocService, Depends(get_soc_service)],
) -> list[FindingRead]:
    return service.list_findings(current_user, investigation_id)


@router.patch(
    "/{investigation_id}/findings/{finding_id}",
    response_model=FindingRead,
)
def update_finding(
    investigation_id: int,
    finding_id: int,
    data: FindingUpdate,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Findings.UPDATE))
    ],
    service: Annotated[SocService, Depends(get_soc_service)],
) -> FindingRead:
    return service.update_finding(current_user, investigation_id, finding_id, data)


@router.post(
    "/{investigation_id}/search-schedules",
    response_model=SearchScheduleRead,
    status_code=status.HTTP_201_CREATED,
)
def create_search_schedule(
    investigation_id: int,
    data: SearchScheduleCreate,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Schedules.CREATE))
    ],
    service: Annotated[SocService, Depends(get_soc_service)],
) -> SearchScheduleRead:
    return service.create_schedule(current_user, investigation_id, data)


@router.get(
    "/{investigation_id}/search-schedules",
    response_model=list[SearchScheduleRead],
)
def list_search_schedules(
    investigation_id: int,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Schedules.READ))
    ],
    service: Annotated[SocService, Depends(get_soc_service)],
) -> list[SearchScheduleRead]:
    return service.list_schedules(current_user, investigation_id)


@router.patch(
    "/{investigation_id}/search-schedules/{schedule_id}",
    response_model=SearchScheduleRead,
)
def update_search_schedule(
    investigation_id: int,
    schedule_id: int,
    data: SearchScheduleUpdate,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Schedules.UPDATE))
    ],
    service: Annotated[SocService, Depends(get_soc_service)],
) -> SearchScheduleRead:
    return service.update_schedule(
        current_user, investigation_id, schedule_id, data
    )
