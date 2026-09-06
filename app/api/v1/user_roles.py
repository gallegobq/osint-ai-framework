from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.user_roles import get_user_role_service
from app.schemas.role import RoleRead
from app.services.user_role_service import UserRoleService
from app.schemas.user_role import UserRoleAssign

router = APIRouter(
    prefix="/users",
    tags=["User Roles"],
)


@router.get(
    "/{user_id}/roles",
    response_model=list[RoleRead],
    dependencies=[
        Depends(
            require_permission(
                Permissions.Users.READ,
            )
        )
    ],
)
def get_user_roles(
    user_id: int,
    service: Annotated[
        UserRoleService,
        Depends(get_user_role_service),
    ],
) -> list[RoleRead]:
    return service.get_roles(
        user_id=user_id,
    )

@router.post(
    "/{user_id}/roles",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Users.UPDATE,
            )
        )
    ],
)
def assign_role(
    user_id: int,
    data: UserRoleAssign,
    service: Annotated[
        UserRoleService,
        Depends(get_user_role_service),
    ],
) -> None:
    service.assign_role(
        user_id=user_id,
        role_id=data.role_id,
    )

@router.delete(
    "/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Users.UPDATE,
            )
        )
    ],
)
def remove_role(
    user_id: int,
    role_id: int,
    service: Annotated[
        UserRoleService,
        Depends(get_user_role_service),
    ],
) -> None:
    service.remove_role(
        user_id=user_id,
        role_id=role_id,
    )
