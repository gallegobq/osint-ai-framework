from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import build_project_service
from app.dependencies.database import get_db
from app.services.project_service import ProjectService


def get_project_service(
    db: Annotated[Session, Depends(get_db)],
) -> ProjectService:
    return build_project_service(db)
