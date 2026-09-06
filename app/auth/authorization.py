from collections.abc import Callable
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.exceptions import ForbiddenException
from app.dependencies.database import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.authorization_service import AuthorizationService


def get_authorization_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> AuthorizationService:
    """
    Construye el servicio de autorización
    usando la sesión de base de datos actual.
    """

    user_repository = UserRepository(db)

    return AuthorizationService(
        user_repository=user_repository,
    )


def require_permission(
    permission_code: str,
) -> Callable:
    """
    Crea una dependencia que exige un permiso específico.
    """

    def dependency(
        current_user: Annotated[
            User,
            Depends(get_current_user),
        ],
        authorization_service: Annotated[
            AuthorizationService,
            Depends(get_authorization_service),
        ],
    ) -> User:

        if current_user.is_superuser:
            return current_user

        if not authorization_service.has_permission(
            user_id=current_user.id,
            permission_code=permission_code,
        ):
            raise ForbiddenException()

        return current_user

    return dependency
