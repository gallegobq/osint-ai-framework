from unittest.mock import Mock

import pytest

from app.auth.totp import totp_code
from app.core.exceptions import BadRequestException
from app.core.security import hash_password
from app.models.user import User
from app.schemas.mfa import MfaSetupRequest, MfaVerifyRequest
from app.services.mfa_service import MfaService


def _user() -> User:
    return User(
        id=7,
        username="analyst",
        email="analyst@example.com",
        hashed_password=hash_password("StrongPassword123!"),
        is_active=True,
    )


def test_mfa_setup_requires_password_step_up() -> None:
    users = Mock()
    sessions = Mock()
    audit = Mock()
    service = MfaService(users, sessions, audit)

    with pytest.raises(BadRequestException):
        service.setup(_user(), MfaSetupRequest(password="wrong"))

    audit.record.assert_called_once()
    users.commit.assert_called_once()


def test_mfa_confirmation_revokes_existing_sessions_and_is_audited() -> None:
    users = Mock()
    sessions = Mock()
    audit = Mock()
    service = MfaService(users, sessions, audit)
    user = _user()

    setup = service.setup(
        user,
        MfaSetupRequest(password="StrongPassword123!"),
    )
    service.confirm(user, MfaVerifyRequest(code=totp_code(setup.secret)))

    assert user.mfa_enabled is True
    sessions.revoke_all_sessions.assert_called_once_with(7, commit=False)
    assert audit.record.call_count == 2
    assert users.commit.call_count == 2
