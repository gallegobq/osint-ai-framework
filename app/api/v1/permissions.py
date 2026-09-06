from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.permissions import get_permission_service
from app.schemas.permission import (
    PermissionCreate,
    PermissionRead,
    PermissionUpdate,
)
from app.services.permission_service import PermissionService


router = APIRouter(
    prefix="/permissions",
    tags=["Permissions"],
)


@router.get(
    "",
    response_model=list[PermissionRead],
    dependencies=[
        Depends(
            require_permission(
                Permissions.Permissions.READ,
            )
        )
    ],
)
def list_permissions(
    service: Annotated[
        PermissionService,
        Depends(get_permission_service),
    ],
) -> list[PermissionRead]:
    return service.list_permissions()


@router.post(
    "",
    response_model=PermissionRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Permissions.CREATE,
            )
        )
    ],
)
def create_permission(
    permission_data: PermissionCreate,
    service: Annotated[
        PermissionService,
        Depends(get_permission_service),
    ],
) -> PermissionRead:
    return service.create_permission(
        data=permission_data,
    )

@router.get(
    "/{permission_id}",
    response_model=PermissionRead,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Permissions.READ,
            )
        )
    ],
)
def get_permission(
    permission_id: int,
    service: Annotated[
        PermissionService,
        Depends(get_permission_service),
    ],
) -> PermissionRead:
    return service.get_permission(permission_id)

@router.patch(
    "/{permission_id}",
    response_model=PermissionRead,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Permissions.UPDATE,
            )
        )
    ],
)
def update_permission(
    permission_id: int,
    permission_data: PermissionUpdate,
    service: Annotated[
        PermissionService,
        Depends(get_permission_service),
    ],
) -> PermissionRead:
    return service.update_permission(
        permission_id=permission_id,
        data=permission_data,
    )

@router.delete(
    "/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Permissions.DELETE,
            )
        )
    ],
)
def delete_permission(
    permission_id: int,
    service: Annotated[
        PermissionService,
        Depends(get_permission_service),
    ],
) -> None:
    service.delete_permission(permission_id)
