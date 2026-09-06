from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.role_permissions import (
    get_role_permission_service,
)
from app.schemas.permission import PermissionRead
from app.schemas.role_permission import RolePermissionAssign
from app.services.role_permission_service import (
    RolePermissionService,
)


router = APIRouter(
    prefix="/roles",
    tags=["Role Permissions"],
)


@router.get(
    "/{role_id}/permissions",
    response_model=list[PermissionRead],
    dependencies=[
        Depends(
            require_permission(
                Permissions.Roles.READ,
            )
        )
    ],
)
def get_role_permissions(
    role_id: int,
    service: Annotated[
        RolePermissionService,
        Depends(get_role_permission_service),
    ],
) -> list[PermissionRead]:
    return service.get_permissions(
        role_id=role_id,
    )


@router.post(
    "/{role_id}/permissions",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Roles.UPDATE,
            )
        )
    ],
)
def assign_permission(
    role_id: int,
    data: RolePermissionAssign,
    service: Annotated[
        RolePermissionService,
        Depends(get_role_permission_service),
    ],
) -> None:
    service.assign_permission(
        role_id=role_id,
        permission_id=data.permission_id,
    )


@router.delete(
    "/{role_id}/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Roles.UPDATE,
            )
        )
    ],
)
def remove_permission(
    role_id: int,
    permission_id: int,
    service: Annotated[
        RolePermissionService,
        Depends(get_role_permission_service),
    ],
) -> None:
    service.remove_permission(
        role_id=role_id,
        permission_id=permission_id,
    )
