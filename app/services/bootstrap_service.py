from datetime import datetime
from datetime import timezone

from sqlalchemy.exc import IntegrityError

from app.core.exceptions import ConflictException
from app.core.security import hash_password
from app.core.security import verify_password
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.user import UserCreate, UserRead
from app.services.session_service import SessionService


class BootstrapService:
    """Create the first superuser from explicit deployment configuration."""

    def __init__(
        self,
        user_repository: UserRepository,
        session_service: SessionService,
    ):
        self.user_repository = user_repository
        self.session_service = session_service

    def create_initial_admin(self, data: UserCreate) -> UserRead:
        existing_superuser = (
            self.user_repository.get_first_active_superuser()
        )

        if existing_superuser is not None:
            return UserRead.model_validate(existing_superuser)

        by_username = self.user_repository.get_by_username(data.username)
        by_email = self.user_repository.get_by_email(str(data.email))

        if by_username is not None or by_email is not None:
            existing = by_username or by_email

            if (
                existing is not None
                and existing.username == data.username
                and existing.email == str(data.email)
                and existing.is_superuser
                and existing.deleted_at is None
            ):
                return UserRead.model_validate(existing)

            raise ConflictException(
                "The configured initial administrator conflicts with "
                "an existing account."
            )

        user = User(
            username=data.username,
            email=str(data.email),
            hashed_password=hash_password(data.password),
            is_superuser=True,
            is_active=True,
        )

        try:
            self.user_repository.create(user)
            self.user_repository.commit()
        except IntegrityError as exc:
            self.user_repository.rollback()
            raise ConflictException(
                "Could not create the initial administrator."
            ) from exc

        return UserRead.model_validate(user)

    def reconcile_initial_admin(self, data: UserCreate) -> UserRead:
        """Adopt configured credentials for one recoverable account."""
        existing = self.user_repository.get_first_active_superuser()
        by_username = self.user_repository.get_by_username(data.username)
        by_email = self.user_repository.get_by_email(str(data.email))

        if (
            by_username is not None
            and by_email is not None
            and by_username.id != by_email.id
        ):
            raise ConflictException(
                "The configured administrator username and email belong "
                "to different accounts. Reconciliation was not performed."
            )

        if existing is None:
            existing = by_username or by_email

        if existing is None:
            return self.create_initial_admin(data)

        for collision in (by_username, by_email):
            if collision is not None and collision.id != existing.id:
                raise ConflictException(
                    "The configured administrator identity belongs to "
                    "another account. Reconciliation was not performed."
                )

        password_changed = not verify_password(
            data.password,
            existing.hashed_password,
        )

        existing.username = data.username
        existing.email = str(data.email)
        existing.is_active = True
        existing.is_superuser = True
        existing.deleted_at = None

        if password_changed:
            existing.hashed_password = hash_password(data.password)
            existing.password_changed_at = datetime.now(timezone.utc)

        self.session_service.revoke_all_sessions(
            existing.id,
            commit=False,
        )

        try:
            self.user_repository.commit()
        except IntegrityError as exc:
            self.user_repository.rollback()
            raise ConflictException(
                "Could not reconcile the initial administrator."
            ) from exc

        return UserRead.model_validate(existing)
