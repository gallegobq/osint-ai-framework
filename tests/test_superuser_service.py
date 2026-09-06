from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from app.core.exceptions import ConflictException
from app.models.role import Role
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.superuser_service import SuperuserService


def make_user(*, username: str, email: str) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=8,
        username=username,
        email=email,
        hashed_password="old-hash",
        password_changed_at=now,
        is_active=False,
        is_superuser=False,
        deleted_at=now,
        created_at=now,
        updated_at=now,
    )


def build_service(users: Mock) -> tuple[SuperuserService, Mock, Mock, Mock]:
    roles = Mock()
    roles.get_by_name.return_value = Role(id=3, name="Administrator")
    user_roles = Mock()
    user_roles.get_by_user_and_role.return_value = None
    sessions = Mock()
    audit = Mock()
    return (
        SuperuserService(users, roles, user_roles, sessions, audit),
        user_roles,
        sessions,
        audit,
    )


def test_promotes_exact_existing_identity_and_revokes_sessions() -> None:
    user = make_user(username="soc-admin", email="soc@example.com")
    users = Mock()
    users.get_by_username.return_value = user
    users.get_by_email.return_value = user
    service, user_roles, sessions, audit = build_service(users)

    with patch(
        "app.services.superuser_service.hash_password", return_value="new-hash"
    ):
        result = service.ensure(
            UserCreate(
                username="soc-admin",
                email="soc@example.com",
                password="StrongPassword123!",
            )
        )

    assert result.is_superuser is True
    assert result.is_active is True
    assert user.deleted_at is None
    assert user.hashed_password == "new-hash"
    sessions.revoke_all_sessions.assert_called_once_with(8, commit=False)
    user_roles.create.assert_called_once()
    audit.record.assert_called_once()
    users.commit.assert_called_once()


def test_rejects_partial_identity_match() -> None:
    user = make_user(username="soc-admin", email="old@example.com")
    users = Mock()
    users.get_by_username.return_value = user
    users.get_by_email.return_value = None
    service, _, _, _ = build_service(users)

    with pytest.raises(ConflictException, match="exactly match"):
        service.ensure(
            UserCreate(
                username="soc-admin",
                email="new@example.com",
                password="StrongPassword123!",
            )
        )

    users.commit.assert_not_called()

