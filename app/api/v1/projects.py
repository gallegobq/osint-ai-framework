from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.projects import get_project_service
from app.models.user import User
from app.schemas.project import (
    ProjectCreate,
    ProjectMemberAssign,
    ProjectMemberRead,
    ProjectRead,
    ProjectUpdate,
)
from app.services.project_service import ProjectService


router = APIRouter(prefix="/projects", tags=["Projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(
    data: ProjectCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Projects.CREATE)),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> ProjectRead:
    return service.create(current_user, data)


@router.get("", response_model=list[ProjectRead])
def list_projects(
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Projects.LIST)),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> list[ProjectRead]:
    return service.list_for_user(current_user)


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(
    project_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Projects.READ)),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> ProjectRead:
    return ProjectRead.model_validate(service.get(current_user, project_id))


@router.patch("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: int,
    data: ProjectUpdate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Projects.UPDATE)),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> ProjectRead:
    return service.update(current_user, project_id, data)


@router.get("/{project_id}/members", response_model=list[ProjectMemberRead])
def list_project_members(
    project_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Projects.READ)),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> list[ProjectMemberRead]:
    return service.list_members(current_user, project_id)


@router.post(
    "/{project_id}/members",
    response_model=ProjectMemberRead,
    status_code=status.HTTP_201_CREATED,
)
def add_project_member(
    project_id: int,
    data: ProjectMemberAssign,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Projects.MANAGE_MEMBERS)),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> ProjectMemberRead:
    return service.add_member(current_user, project_id, data)


@router.delete(
    "/{project_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_project_member(
    project_id: int,
    user_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Projects.MANAGE_MEMBERS)),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
) -> None:
    service.remove_member(current_user, project_id, user_id)
