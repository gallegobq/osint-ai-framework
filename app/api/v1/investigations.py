from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.investigations import get_investigation_service
from app.models.user import User
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationRead,
    InvestigationTaskCreate,
    InvestigationTaskRead,
    InvestigationTaskUpdate,
    InvestigationUpdate,
    RetentionPolicyUpdate,
)
from app.services.investigation_service import InvestigationService


router = APIRouter(tags=["Investigations"])


@router.post(
    "/projects/{project_id}/investigations",
    response_model=InvestigationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation(
    project_id: int,
    data: InvestigationCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Investigations.CREATE)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> InvestigationRead:
    return service.create(current_user, project_id, data)


@router.get(
    "/projects/{project_id}/investigations",
    response_model=list[InvestigationRead],
)
def list_investigations(
    project_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Investigations.READ)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> list[InvestigationRead]:
    return service.list(current_user, project_id)


@router.get("/investigations/{investigation_id}", response_model=InvestigationRead)
def get_investigation(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Investigations.READ)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> InvestigationRead:
    return service.get(current_user, investigation_id)


@router.patch(
    "/investigations/{investigation_id}",
    response_model=InvestigationRead,
)
def update_investigation(
    investigation_id: int,
    data: InvestigationUpdate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Investigations.UPDATE)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> InvestigationRead:
    return service.update(current_user, investigation_id, data)


@router.patch(
    "/investigations/{investigation_id}/retention",
    response_model=InvestigationRead,
)
def update_investigation_retention(
    investigation_id: int,
    data: RetentionPolicyUpdate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Governance.MANAGE_RETENTION)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> InvestigationRead:
    return service.update_retention(current_user, investigation_id, data)


@router.post(
    "/investigations/{investigation_id}/tasks",
    response_model=InvestigationTaskRead,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation_task(
    investigation_id: int,
    data: InvestigationTaskCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Investigations.UPDATE)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> InvestigationTaskRead:
    return service.create_task(current_user, investigation_id, data)


@router.get(
    "/investigations/{investigation_id}/tasks",
    response_model=list[InvestigationTaskRead],
)
def list_investigation_tasks(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Investigations.READ)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> list[InvestigationTaskRead]:
    return service.list_tasks(current_user, investigation_id)


@router.patch(
    "/investigations/{investigation_id}/tasks/{task_id}",
    response_model=InvestigationTaskRead,
)
def update_investigation_task(
    investigation_id: int,
    task_id: int,
    data: InvestigationTaskUpdate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Investigations.UPDATE)),
    ],
    service: Annotated[
        InvestigationService,
        Depends(get_investigation_service),
    ],
) -> InvestigationTaskRead:
    return service.update_task(current_user, investigation_id, task_id, data)
