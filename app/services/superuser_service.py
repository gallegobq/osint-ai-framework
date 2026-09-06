from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from app.core.exceptions import ConflictException
from app.core.security import hash_password
from app.models.user import User
from app.models.user_role import UserRole
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_role_repository import UserRoleRepository
from app.schemas.user import UserCreate, UserRead
from app.services.audit_service import AuditService
from app.services.session_service import SessionService


class SuperuserService:
    """Crea o promueve una identidad exacta desde la consola del servidor."""

    administrator_role_name = "Administrator"

    def __init__(
        self,
        users: UserRepository,
        roles: RoleRepository,
        user_roles: UserRoleRepository,
        sessions: SessionService,
        audit: AuditService,
    ):
        self.users = users
        self.roles = roles
        self.user_roles = user_roles
        self.sessions = sessions
        self.audit = audit

    def ensure(self, data: UserCreate) -> UserRead:
        by_username = self.users.get_by_username(data.username)
        by_email = self.users.get_by_email(str(data.email))
        if (
            by_username is not None
            and by_email is not None
            and by_username.id != by_email.id
        ):
            raise ConflictException(
                "Username and email belong to different accounts."
            )

        user = by_username or by_email
        if user is not None and (
            user.username != data.username or user.email != str(data.email)
        ):
            raise ConflictException(
                "The existing account identity does not exactly match."
            )

        administrator = self.roles.get_by_name(self.administrator_role_name)
        if administrator is None:
            raise RuntimeError(
                "Administrator role is missing. Run python -m app.seed.rbac first."
            )

        created = user is None
        if created:
            user = self.users.create(
                User(
                    username=data.username,
                    email=str(data.email),
                    hashed_password=hash_password(data.password),
                    password_changed_at=datetime.now(timezone.utc),
                    is_active=True,
                    is_superuser=True,
                )
            )
        else:
            user.hashed_password = hash_password(data.password)
            user.password_changed_at = datetime.now(timezone.utc)
            user.is_active = True
            user.is_superuser = True
            user.deleted_at = None
            self.sessions.revoke_all_sessions(user.id, commit=False)

        if self.user_roles.get_by_user_and_role(user.id, administrator.id) is None:
            self.user_roles.create(
                UserRole(user_id=user.id, role_id=administrator.id)
            )

        self.audit.record(
            actor_user_id=user.id,
            action="users.superuser.create" if created else "users.superuser.promote",
            resource_type="user",
            resource_id=user.id,
        )
        try:
            self.users.commit()
        except IntegrityError as exc:
            self.users.rollback()
            raise ConflictException("Could not create the superuser.") from exc
        return UserRead.model_validate(user)

