from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db

from app.repositories.user_repository import UserRepository
from app.repositories.user_session_repository import UserSessionRepository

from app.services.session_service import SessionService
from app.services.auth_session_service import AuthSessionService


def get_auth_session_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> AuthSessionService:
    """
    Construye AuthSessionService con
    todas sus dependencias.
    """

    user_repository = UserRepository(
        db,
    )

    session_repository = UserSessionRepository(
        db,
    )

    session_service = SessionService(
        session_repository,
    )

    return AuthSessionService(
        user_repository=user_repository,
        session_service=session_service,
    )
