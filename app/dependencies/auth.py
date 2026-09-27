from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db

from app.repositories.user_repository import UserRepository
from app.repositories.user_session_repository import UserSessionRepository
from app.repositories.audit_repository import AuditRepository

from app.services.session_service import SessionService
from app.auth.service import AuthenticationService
from app.services.mfa_service import MfaService
from app.services.audit_service import AuditService


def get_auth_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> AuthenticationService:

    user_repository = UserRepository(db)

    session_repository = UserSessionRepository(db)

    session_service = SessionService(
        session_repository
    )

    return AuthenticationService(
        repository=user_repository,
        session_service=session_service,
        audit_service=AuditService(AuditRepository(db)),
    )


def get_mfa_service(
    db: Annotated[
        Session,
        Depends(get_db),
    ],
) -> MfaService:
    return MfaService(
        users=UserRepository(db),
        sessions=SessionService(UserSessionRepository(db)),
        audit=AuditService(AuditRepository(db)),
    )
