from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import build_soc_service
from app.dependencies.database import get_db
from app.services.soc_service import SocService


def get_soc_service(
    db: Annotated[Session, Depends(get_db)],
) -> SocService:
    return build_soc_service(db)
