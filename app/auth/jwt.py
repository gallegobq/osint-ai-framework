"""Creación y validación de JSON Web Tokens."""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from jwt.exceptions import InvalidTokenError

from app.core.settings import settings


def create_access_token(subject: str) -> tuple[str, str]:
    """Genera un access token y devuelve el token junto con su JTI."""

    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    payload = {
        "sub": subject,
        "type": "access",
        "jti": jti,
        "iat": now,
        "exp": now
        + timedelta(minutes=settings.access_token_expire_minutes),
    }

    token = jwt.encode(
        payload,
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return token, jti


def create_refresh_token(subject: str) -> tuple[str, str]:
    """Genera un refresh token y devuelve el token junto con su JTI."""

    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    payload = {
        "sub": subject,
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(days=settings.refresh_token_expire_days),
    }

    token = jwt.encode(
        payload,
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return token, jti


def decode_token(token: str) -> dict[str, Any]:
    """Decodifica un JWT y valida firma, algoritmo y claims obligatorios."""

    return jwt.decode(
        token,
        settings.secret_key.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        options={"require": ["sub", "type", "jti", "iat", "exp"]},
    )


def validate_token_type(
    payload: dict[str, Any],
    expected_type: str,
) -> None:
    """Valida el tipo de token."""

    if payload.get("type") != expected_type:
        raise InvalidTokenError("Invalid token type.")
