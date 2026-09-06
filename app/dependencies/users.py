from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.repositories.user_repository import UserRepository
from app.services.session_service import SessionService
from app.services.user_service import UserService
from app.dependencies.session import get_session_service


def get_user_repository(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> UserRepository:

    return UserRepository(db)


def get_user_service(
    repository: Annotated[
        UserRepository,
        Depends(get_user_repository),
    ],
    session_service: Annotated[
        SessionService,
        Depends(get_session_service),
    ],
) -> UserService:

    return UserService(repository, session_service)
