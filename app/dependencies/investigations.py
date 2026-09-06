from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import build_investigation_service
from app.dependencies.database import get_db
from app.services.investigation_service import InvestigationService


def get_investigation_service(
    db: Annotated[Session, Depends(get_db)],
) -> InvestigationService:
    return build_investigation_service(db)
