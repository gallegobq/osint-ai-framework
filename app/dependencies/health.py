from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.services.health_service import HealthService


def get_health_service(
    db: Annotated[Session, Depends(get_db)],
) -> HealthService:
    return HealthService(db)
