from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_role_repository import UserRoleRepository
from app.services.user_role_service import UserRoleService


def get_user_role_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> UserRoleService:
    user_repository = UserRepository(db)
    role_repository = RoleRepository(db)
    user_role_repository = UserRoleRepository(db)

    return UserRoleService(
        user_repository=user_repository,
        role_repository=role_repository,
        repository=user_role_repository,
    )
