from datetime import datetime, timezone
from unittest.mock import Mock

from app.models.user import User
from app.services.user_service import UserService


def make_user(*, is_active: bool = True) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=1,
        username="analyst",
        email="analyst@example.com",
        hashed_password="hash",
        password_changed_at=now,
        is_active=is_active,
        is_superuser=False,
        created_at=now,
        updated_at=now,
    )


def test_deactivate_user_revokes_sessions_in_same_unit_of_work() -> None:
    repository = Mock()
    repository.get_by_id.return_value = make_user()
    session_service = Mock()
    service = UserService(repository, session_service)

    result = service.deactivate_user(1)

    assert result.is_active is False
    session_service.revoke_all_sessions.assert_called_once_with(
        1,
        commit=False,
    )
    repository.commit.assert_called_once_with()


def test_restore_user_keeps_account_inactive() -> None:
    repository = Mock()
    user = make_user(is_active=False)
    user.deleted_at = datetime.now(timezone.utc)
    repository.get_by_id_including_deleted.return_value = user
    service = UserService(repository, Mock())

    result = service.restore_user(1)

    assert result.deleted_at is None
    assert result.is_active is False
    repository.commit.assert_called_once_with()
