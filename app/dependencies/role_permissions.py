from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.repositories.permission_repository import PermissionRepository
from app.repositories.role_permission_repository import (
    RolePermissionRepository,
)
from app.repositories.role_repository import RoleRepository
from app.services.role_permission_service import (
    RolePermissionService,
)


def get_role_permission_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> RolePermissionService:
    role_repository = RoleRepository(db)
    permission_repository = PermissionRepository(db)
    repository = RolePermissionRepository(db)

    return RolePermissionService(
        role_repository=role_repository,
        permission_repository=permission_repository,
        repository=repository,
    )
