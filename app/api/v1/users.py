from datetime import datetime
from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from fastapi import status

from app.auth.authorization import (
    get_authorization_service,
    require_permission,
)
from app.core.exceptions import ForbiddenException
from app.core.permissions import Permissions
from app.dependencies.users import get_user_service
from app.models.user import User
from app.schemas.user import (
    UserChangePassword,
    UserCreate,
    UserRead,
    UserResetPassword,
    UserUpdate,
)
from app.schemas.user_query import (
    SortOrder,
    UserListQuery,
    UserListResponse,
    UserSortField,
)
from app.services.authorization_service import AuthorizationService
from app.services.user_service import UserService


router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Users.CREATE
            )
        )
    ],
)
def create_user(
    user: UserCreate,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> UserRead:
    """
    Create a new user.

    Requires the users:create permission.
    """
    return service.create_user(user)


@router.get(
    "",
    response_model=UserListResponse,
    status_code=status.HTTP_200_OK,
)
def list_users(
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permissions.Users.LIST
            )
        ),
    ],
    authorization_service: Annotated[
        AuthorizationService,
        Depends(get_authorization_service),
    ],
    page: Annotated[
        int,
        Query(
            ge=1,
            description="Número de página, comenzando en 1.",
        ),
    ] = 1,
    page_size: Annotated[
        int,
        Query(
            ge=1,
            le=100,
            description="Cantidad de usuarios por página.",
        ),
    ] = 20,
    search: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=100,
            description="Búsqueda por username o email.",
        ),
    ] = None,
    is_active: Annotated[
        bool | None,
        Query(
            description="Filtrar por estado activo.",
        ),
    ] = None,
    is_deleted: Annotated[
        bool,
        Query(
            description=(
                "Consultar usuarios eliminados lógicamente. "
                "Requiere users:read_deleted."
            ),
        ),
    ] = False,
    role_id: Annotated[
        int | None,
        Query(
            ge=1,
            description="Filtrar por ID de rol.",
        ),
    ] = None,
    created_from: Annotated[
        datetime | None,
        Query(
            description=(
                "Fecha mínima de creación en formato ISO 8601."
            ),
        ),
    ] = None,
    created_to: Annotated[
        datetime | None,
        Query(
            description=(
                "Fecha máxima de creación en formato ISO 8601."
            ),
        ),
    ] = None,
    sort_by: Annotated[
        UserSortField,
        Query(
            description="Campo utilizado para ordenar.",
        ),
    ] = UserSortField.CREATED_AT,
    sort_order: Annotated[
        SortOrder,
        Query(
            description="Dirección del ordenamiento.",
        ),
    ] = SortOrder.DESC,
) -> UserListResponse:
    """
    List users with pagination, filtering, searching and sorting.

    Requesting soft-deleted users requires both users:list and
    users:read_deleted.
    """
    if (
        is_deleted
        and not current_user.is_superuser
        and not authorization_service.has_permission(
            user_id=current_user.id,
            permission_code=Permissions.Users.READ_DELETED,
        )
    ):
        raise ForbiddenException()

    query = UserListQuery(
        page=page,
        page_size=page_size,
        search=search,
        is_active=is_active,
        is_deleted=is_deleted,
        role_id=role_id,
        created_from=created_from,
        created_to=created_to,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    return service.list_users(query)


@router.post(
    "/me/password",
    status_code=status.HTTP_204_NO_CONTENT,
)
def change_own_password(
    data: UserChangePassword,
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permissions.Users.CHANGE_OWN_PASSWORD
            )
        ),
    ],
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> None:
    service.change_own_password(current_user.id, data)


@router.get(
    "/{user_id}",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
)
def get_user(
    user_id: int,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permissions.Users.READ
            )
        ),
    ],
    authorization_service: Annotated[
        AuthorizationService,
        Depends(get_authorization_service),
    ],
    include_deleted: Annotated[
        bool,
        Query(
            description=(
                "Permite consultar el usuario aunque esté eliminado. "
                "Requiere users:read_deleted."
            ),
        ),
    ] = False,
) -> UserRead:
    """
    Retrieve one user by identifier.

    Deleted users remain hidden unless include_deleted=true and the caller has
    the users:read_deleted permission.
    """
    if (
        include_deleted
        and not current_user.is_superuser
        and not authorization_service.has_permission(
            user_id=current_user.id,
            permission_code=Permissions.Users.READ_DELETED,
        )
    ):
        raise ForbiddenException()

    return service.get_user(
        user_id,
        include_deleted=include_deleted,
    )


@router.patch(
    "/{user_id}",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Users.UPDATE
            )
        )
    ],
)
def update_user(
    user_id: int,
    data: UserUpdate,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> UserRead:
    """
    Update the mutable identity fields of a non-deleted user.

    Account status, credentials, roles, deletion state and superuser
    privileges cannot be changed through this endpoint.
    """
    return service.update_user(
        user_id,
        data,
    )


@router.post(
    "/{user_id}/password/reset",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_permission(
                Permissions.Users.RESET_PASSWORD
            )
        )
    ],
)
def reset_password(
    user_id: int,
    data: UserResetPassword,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> None:
    service.reset_password(user_id, data)


@router.post(
    "/{user_id}/activate",
    response_model=UserRead,
    dependencies=[
        Depends(
            require_permission(Permissions.Users.ACTIVATE)
        )
    ],
)
def activate_user(
    user_id: int,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> UserRead:
    return service.activate_user(user_id)


@router.post(
    "/{user_id}/deactivate",
    response_model=UserRead,
    dependencies=[
        Depends(
            require_permission(Permissions.Users.DEACTIVATE)
        )
    ],
)
def deactivate_user(
    user_id: int,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> UserRead:
    return service.deactivate_user(user_id)


@router.delete(
    "/{user_id}",
    response_model=UserRead,
    dependencies=[
        Depends(
            require_permission(Permissions.Users.DELETE)
        )
    ],
)
def delete_user(
    user_id: int,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> UserRead:
    return service.delete_user(user_id)


@router.post(
    "/{user_id}/restore",
    response_model=UserRead,
    dependencies=[
        Depends(
            require_permission(Permissions.Users.RESTORE)
        )
    ],
)
def restore_user(
    user_id: int,
    service: Annotated[
        UserService,
        Depends(get_user_service),
    ],
) -> UserRead:
    return service.restore_user(user_id)
