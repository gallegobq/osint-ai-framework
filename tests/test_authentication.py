from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from app.auth.schemas import LoginRequest
from app.auth.service import AuthenticationService
from app.core.exceptions import InvalidCredentialsException
from app.models.user import User
from app.models.user_session import UserSession
from app.services.session_service import SessionService
from app.auth.totp import generate_totp_secret, totp_code, verify_totp


def test_login_rejects_inactive_user() -> None:
    repository = Mock()
    repository.get_by_username.return_value = User(
        id=1,
        username="inactive",
        email="inactive@example.com",
        hashed_password="not-used",
        is_active=False,
    )
    session_service = Mock()
    service = AuthenticationService(repository, session_service)

    with pytest.raises(InvalidCredentialsException):
        service.login(
            LoginRequest(username="inactive", password="Password123!")
        )

    session_service.create_session.assert_not_called()


def test_expired_refresh_session_is_rejected() -> None:
    repository = Mock()
    repository.get_by_jti.return_value = UserSession(
        id=1,
        user_id=1,
        jti="refresh-jti",
        access_jti="access-jti",
        refresh_token_hash="hash",
        last_used_at=datetime.now(timezone.utc) - timedelta(days=8),
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    service = SessionService(repository)

    with pytest.raises(InvalidCredentialsException):
        service.get_valid_session("refresh-jti")

    repository.revoke.assert_called_once()
    repository.commit.assert_called_once()


def test_refresh_reuse_revokes_all_active_user_sessions() -> None:
    repository = Mock()
    repository.get_by_jti.return_value = UserSession(
        id=1,
        user_id=7,
        jti="reused-jti",
        access_jti="access-jti",
        refresh_token_hash="hash",
        last_used_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        revoked_at=datetime.now(timezone.utc),
    )
    service = SessionService(repository)

    from app.core.exceptions import RefreshTokenReuseException

    with pytest.raises(RefreshTokenReuseException):
        service.get_valid_session("reused-jti")

    repository.revoke_all.assert_called_once_with(7)
    repository.commit.assert_called_once()


def test_totp_generation_and_verification() -> None:
    secret = generate_totp_secret()
    timestamp = 1_800_000_000
    code = totp_code(secret, timestamp=timestamp)

    assert len(code) == 6
    assert verify_totp(secret, code, timestamp=timestamp)
    assert not verify_totp(secret, "000000", timestamp=timestamp)
