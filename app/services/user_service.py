from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from app.core.exceptions import (
    ConflictException,
    EmailAlreadyExistsException,
    InvalidCredentialsException,
    NotFoundException,
    UsernameAlreadyExistsException,
)
from app.core.security import hash_password, verify_password
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.user import (
    UserCreate,
    UserChangePassword,
    UserRead,
    UserResetPassword,
    UserUpdate,
)
from app.schemas.user_query import (
    PaginationMetadata,
    UserListQuery,
    UserListResponse,
)
from app.services.session_service import SessionService


class UserService:
    """
    Casos de uso relacionados con la gestión de usuarios.

    El servicio contiene validaciones de negocio y coordinación transaccional.
    El repositorio se limita al acceso persistente y construcción de consultas.
    """

    def __init__(
        self,
        repository: UserRepository,
        session_service: SessionService,
    ):
        self.repository = repository
        self.session_service = session_service

    def create_user(
        self,
        data: UserCreate,
    ) -> UserRead:
        """
        Create a user after validating unique identity fields.
        """
        if self.repository.get_by_username(data.username):
            raise UsernameAlreadyExistsException()

        if self.repository.get_by_email(str(data.email)):
            raise EmailAlreadyExistsException()

        user = User(
            username=data.username,
            email=str(data.email),
            hashed_password=hash_password(data.password),
        )

        try:
            self.repository.create(user)
            self.repository.commit()

            return UserRead.model_validate(user)

        except IntegrityError as exc:
            self.repository.rollback()

            raise ConflictException(
                "Database integrity error while creating user."
            ) from exc

    def list_users(
        self,
        query: UserListQuery,
    ) -> UserListResponse:
        """
        Return users matching the validated administrative query.

        Authorization to request soft-deleted users must be enforced by the
        API authorization layer before invoking this method.
        """
        users, total_items = self.repository.list_users(query)

        total_pages = (
            total_items + query.page_size - 1
        ) // query.page_size

        pagination = PaginationMetadata(
            page=query.page,
            page_size=query.page_size,
            total_items=total_items,
            total_pages=total_pages,
            has_previous=query.page > 1,
            has_next=query.page < total_pages,
        )

        return UserListResponse(
            items=[
                UserRead.model_validate(user)
                for user in users
            ],
            pagination=pagination,
        )

    def get_user(
        self,
        user_id: int,
        *,
        include_deleted: bool = False,
    ) -> UserRead:
        """
        Retrieve one user.

        Deleted users are hidden by default. The caller may request them only
        after verifying the dedicated read-deleted permission.
        """
        if include_deleted:
            user = self.repository.get_by_id_including_deleted(
                user_id
            )
        else:
            user = self.repository.get_by_id(user_id)

        if user is None:
            raise NotFoundException("User")

        return UserRead.model_validate(user)

    def update_user(
        self,
        user_id: int,
        data: UserUpdate,
    ) -> UserRead:
        """
        Update mutable identity fields of a non-deleted user.

        Account status, superuser privileges, credentials, roles and deletion
        state are intentionally excluded from this use case.
        """
        user = self.repository.get_by_id(user_id)

        if user is None:
            raise NotFoundException("User")

        update_data = data.model_dump(
            exclude_unset=True,
        )

        new_username = update_data.get("username")

        if (
            new_username is not None
            and new_username != user.username
        ):
            existing_user = self.repository.get_by_username(
                new_username
            )

            if (
                existing_user is not None
                and existing_user.id != user.id
            ):
                raise UsernameAlreadyExistsException()

        new_email = update_data.get("email")

        if new_email is not None:
            new_email = str(new_email)
            update_data["email"] = new_email

        if (
            new_email is not None
            and new_email != user.email
        ):
            existing_user = self.repository.get_by_email(
                new_email
            )

            if (
                existing_user is not None
                and existing_user.id != user.id
            ):
                raise EmailAlreadyExistsException()

        for field_name, value in update_data.items():
            setattr(
                user,
                field_name,
                value,
            )

        try:
            self.repository.commit()

            return UserRead.model_validate(user)

        except IntegrityError as exc:
            self.repository.rollback()

            raise ConflictException(
                "Database integrity error while updating user."
            ) from exc

    def change_own_password(
        self,
        user_id: int,
        data: UserChangePassword,
    ) -> None:
        user = self._get_active_user(user_id)

        if not verify_password(
            data.current_password,
            user.hashed_password,
        ):
            raise InvalidCredentialsException()

        self._set_password(user, data.new_password)

    def reset_password(
        self,
        user_id: int,
        data: UserResetPassword,
    ) -> None:
        user = self._get_active_user(user_id)
        self._set_password(user, data.new_password)

    def activate_user(self, user_id: int) -> UserRead:
        user = self._get_active_user(user_id)

        if user.is_active:
            raise ConflictException("User is already active.")

        user.is_active = True
        self.repository.commit()
        return UserRead.model_validate(user)

    def deactivate_user(self, user_id: int) -> UserRead:
        user = self._get_active_user(user_id)

        if not user.is_active:
            raise ConflictException("User is already inactive.")

        user.is_active = False
        self.session_service.revoke_all_sessions(
            user.id,
            commit=False,
        )
        self.repository.commit()
        return UserRead.model_validate(user)

    def delete_user(self, user_id: int) -> UserRead:
        user = self._get_active_user(user_id)

        user.deleted_at = datetime.now(timezone.utc)
        user.is_active = False
        self.session_service.revoke_all_sessions(
            user.id,
            commit=False,
        )
        self.repository.commit()
        return UserRead.model_validate(user)

    def restore_user(self, user_id: int) -> UserRead:
        user = self.repository.get_by_id_including_deleted(user_id)

        if user is None:
            raise NotFoundException("User")

        if user.deleted_at is None:
            raise ConflictException("User is not deleted.")

        user.deleted_at = None
        self.repository.commit()
        return UserRead.model_validate(user)

    def _get_active_user(self, user_id: int) -> User:
        user = self.repository.get_by_id(user_id)

        if user is None:
            raise NotFoundException("User")

        return user

    def _set_password(self, user: User, password: str) -> None:
        if verify_password(password, user.hashed_password):
            raise ConflictException(
                "The new password must differ from the current password."
            )

        user.hashed_password = hash_password(password)
        user.password_changed_at = datetime.now(timezone.utc)
        self.session_service.revoke_all_sessions(
            user.id,
            commit=False,
        )
        self.repository.commit()
