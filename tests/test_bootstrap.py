from datetime import datetime
from datetime import timezone
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from app.core.exceptions import ConflictException
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.bootstrap_service import BootstrapService


def make_user(
    *,
    username: str,
    email: str,
    is_superuser: bool,
) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=7,
        username=username,
        email=email,
        hashed_password="hash",
        password_changed_at=now,
        is_active=True,
        is_superuser=is_superuser,
        deleted_at=None,
        created_at=now,
        updated_at=now,
    )


def configured_admin() -> UserCreate:
    return UserCreate(
        username="configured-admin",
        email="configured-admin@example.com",
        password="Password123!",
    )


def test_bootstrap_preserves_existing_active_superuser() -> None:
    repository = Mock()
    repository.get_first_active_superuser.return_value = make_user(
        username="existing-admin",
        email="existing-admin@example.com",
        is_superuser=True,
    )
    service = BootstrapService(repository, Mock())

    result = service.create_initial_admin(configured_admin())

    assert result.username == "existing-admin"
    repository.get_by_username.assert_not_called()
    repository.get_by_email.assert_not_called()
    repository.create.assert_not_called()
    repository.commit.assert_not_called()


def test_bootstrap_rejects_collision_without_active_superuser() -> None:
    repository = Mock()
    repository.get_first_active_superuser.return_value = None
    repository.get_by_username.return_value = make_user(
        username="configured-admin",
        email="different@example.com",
        is_superuser=False,
    )
    repository.get_by_email.return_value = None
    service = BootstrapService(repository, Mock())

    with pytest.raises(ConflictException):
        service.create_initial_admin(configured_admin())

    repository.create.assert_not_called()
    repository.commit.assert_not_called()


def test_reconcile_adopts_config_and_revokes_old_sessions() -> None:
    repository = Mock()
    existing = make_user(
        username="existing-admin",
        email="existing-admin@example.com",
        is_superuser=True,
    )
    repository.get_first_active_superuser.return_value = existing
    repository.get_by_username.return_value = None
    repository.get_by_email.return_value = None
    session_service = Mock()
    service = BootstrapService(repository, session_service)

    with (
        patch(
            "app.services.bootstrap_service.verify_password",
            return_value=False,
        ),
        patch(
            "app.services.bootstrap_service.hash_password",
            return_value="new-hash",
        ),
    ):
        result = service.reconcile_initial_admin(configured_admin())

    assert result.username == "configured-admin"
    assert str(result.email) == "configured-admin@example.com"
    assert existing.hashed_password == "new-hash"
    session_service.revoke_all_sessions.assert_called_once_with(
        existing.id,
        commit=False,
    )
    repository.commit.assert_called_once_with()


def test_reconcile_promotes_matching_account_when_no_admin_exists() -> None:
    repository = Mock()
    existing = make_user(
        username="configured-admin",
        email="configured-admin@example.com",
        is_superuser=False,
    )
    existing.is_active = False
    existing.deleted_at = datetime.now(timezone.utc)
    repository.get_first_active_superuser.return_value = None
    repository.get_by_username.return_value = existing
    repository.get_by_email.return_value = existing
    session_service = Mock()
    service = BootstrapService(repository, session_service)

    with (
        patch(
            "app.services.bootstrap_service.verify_password",
            return_value=False,
        ),
        patch(
            "app.services.bootstrap_service.hash_password",
            return_value="recovered-hash",
        ),
    ):
        result = service.reconcile_initial_admin(configured_admin())

    assert result.is_superuser is True
    assert result.is_active is True
    assert result.deleted_at is None
    assert existing.hashed_password == "recovered-hash"
    session_service.revoke_all_sessions.assert_called_once_with(
        existing.id,
        commit=False,
    )
    repository.commit.assert_called_once_with()
