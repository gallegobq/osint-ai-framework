from typing import Annotated

from fastapi import Depends

from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.repositories.user_session_repository import UserSessionRepository
from app.services.session_service import SessionService


def get_session_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> SessionService:

    repository = UserSessionRepository(db)

    return SessionService(repository)
