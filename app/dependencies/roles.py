from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.repositories.role_repository import RoleRepository
from app.repositories.user_role_repository import UserRoleRepository
from app.services.role_service import RoleService


def get_role_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> RoleService:

    role_repository = RoleRepository(db)
    user_role_repository = UserRoleRepository(db)

    return RoleService(
        repository=role_repository,
        user_role_repository=user_role_repository,
    )
