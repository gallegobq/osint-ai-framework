from unittest.mock import Mock

from app.models.user import User
from app.models.user_session import UserSession
from app.services.auth_session_service import AuthSessionService


def _service() -> tuple[AuthSessionService, Mock, Mock]:
    users = Mock()
    sessions = Mock()
    sessions.repository = Mock()
    audit = Mock()
    return AuthSessionService(users, sessions, audit), sessions, audit


def test_logout_revocation_and_audit_share_one_commit() -> None:
    service, sessions, audit = _service()
    session = UserSession(id=4, user_id=7)

    service.logout(session)

    sessions.revoke_session.assert_called_once_with(session, commit=False)
    audit.record.assert_called_once()
    sessions.repository.commit.assert_called_once()


def test_logout_all_revocation_and_audit_share_one_commit() -> None:
    service, sessions, audit = _service()
    user = User(id=7, username="analyst", email="a@example.com")

    service.logout_all(user)

    sessions.revoke_all_sessions.assert_called_once_with(7, commit=False)
    audit.record.assert_called_once()
    sessions.repository.commit.assert_called_once()


def test_owned_session_revocation_is_audited() -> None:
    service, sessions, audit = _service()
    user = User(id=7, username="analyst", email="a@example.com")
    session = UserSession(id=9, user_id=7)
    sessions.get_owned_session.return_value = session

    service.revoke_user_session(user, 9)

    sessions.get_owned_session.assert_called_once_with(7, 9)
    sessions.revoke_session.assert_called_once_with(session, commit=False)
    audit.record.assert_called_once()
    sessions.repository.commit.assert_called_once()
