from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.repositories.permission_repository import PermissionRepository
from app.services.permission_service import PermissionService


def get_permission_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> PermissionService:
    repository = PermissionRepository(db)

    return PermissionService(
        repository=repository,
    )
