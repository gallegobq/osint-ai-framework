from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from fastapi import status

from app.auth.authorization import require_permission
from app.auth.dependencies import get_current_user
from app.core.permissions import Permissions
from app.dependencies.roles import get_role_service
from app.schemas.role import RoleCreate
from app.schemas.role import RoleRead
from app.services.role_service import RoleService
from app.models.user import User

from app.schemas.role import RoleUpdate

router = APIRouter(
    prefix="/roles",
    tags=["Roles"],
)


@router.get(
    "",
    response_model=list[RoleRead],
    dependencies=[
        Depends(
            require_permission(Permissions.Roles.READ),
        )
    ],
)
def list_roles(
    service: Annotated[
        RoleService,
        Depends(get_role_service),
    ],
) -> list[RoleRead]:
    return service.list_roles()


@router.post(
    "",
    response_model=RoleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_permission(Permissions.Roles.CREATE),
        )
    ],
)
def create_role(
    role_data: RoleCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[
        RoleService,
        Depends(get_role_service),
    ],
) -> RoleRead:
    return service.create_role(role_data, actor_user_id=current_user.id)


@router.get(
    "/{role_id}",
    response_model=RoleRead,
    dependencies=[
        Depends(
            require_permission(Permissions.Roles.READ),
        )
    ],
)
def get_role(
    role_id: int,
    service: Annotated[
        RoleService,
        Depends(get_role_service),
    ],
) -> RoleRead:
    return service.get_role(role_id)

@router.patch(
    "/{role_id}",
    response_model=RoleRead,
    dependencies=[
        Depends(
            require_permission(Permissions.Roles.UPDATE),
        )
    ],
)
def update_role(
    role_id: int,
    role_data: RoleUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[
        RoleService,
        Depends(get_role_service),
    ],
) -> RoleRead:
    return service.update_role(
        role_id=role_id,
        data=role_data,
        actor_user_id=current_user.id,
    )
    
@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_permission(Permissions.Roles.DELETE),
        )
    ],
)
def delete_role(
    role_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[
        RoleService,
        Depends(get_role_service),
    ],
) -> None:
    service.delete_role(role_id, actor_user_id=current_user.id)
