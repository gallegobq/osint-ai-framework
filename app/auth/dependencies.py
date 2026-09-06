from typing import Annotated, Any

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session

from app.auth.jwt import decode_token
from app.core.exceptions import (
    InvalidCredentialsException,
    InvalidTokenException,
)
from app.dependencies.database import get_db
from app.models.user import User
from app.models.user_session import UserSession
from app.repositories.user_repository import UserRepository
from app.repositories.user_session_repository import UserSessionRepository
from app.services.session_service import SessionService


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def get_token_payload(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> dict[str, Any]:
    """Decodifica y valida un access token."""

    try:
        payload = decode_token(token)
    except InvalidTokenError as exc:
        raise InvalidCredentialsException() from exc

    if payload.get("type") != "access":
        raise InvalidCredentialsException()
    return payload


def _payload_user_id(payload: dict[str, Any]) -> int:
    try:
        return int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidTokenException() from exc


def get_current_user(
    payload: Annotated[dict[str, Any], Depends(get_token_payload)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Obtiene el usuario y valida la propiedad de la sesión activa."""

    access_jti = payload.get("jti")
    if not isinstance(access_jti, str):
        raise InvalidTokenException()

    user_id = _payload_user_id(payload)
    session_service = SessionService(UserSessionRepository(db))
    session = session_service.get_active_session_by_access_jti(access_jti)
    if session.user_id != user_id:
        raise InvalidTokenException()

    user = UserRepository(db).get_by_id(user_id)
    if user is None or not user.is_active or user.deleted_at is not None:
        raise InvalidTokenException()
    return user


def get_current_session(
    payload: Annotated[dict[str, Any], Depends(get_token_payload)],
    db: Annotated[Session, Depends(get_db)],
) -> UserSession:
    """Obtiene una sesión activa y valida que pertenezca al JWT."""

    access_jti = payload.get("jti")
    if not isinstance(access_jti, str):
        raise InvalidTokenException()

    session = SessionService(
        UserSessionRepository(db)
    ).get_active_session_by_access_jti(access_jti)
    if session.user_id != _payload_user_id(payload):
        raise InvalidTokenException()
    return session
