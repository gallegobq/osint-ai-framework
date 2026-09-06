from app.core.exceptions import (
    ConflictException,
    NotFoundException,
)

from app.models.user_role import UserRole

from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_role_repository import (
    UserRoleRepository,
)


class UserRoleService:
    """
    Administración de asignaciones Usuario ↔ Rol.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        repository: UserRoleRepository,
    ):
        self.user_repository = user_repository
        self.role_repository = role_repository
        self.repository = repository

    def assign_role(
        self,
        user_id: int,
        role_id: int,
    ) -> None:

        user = self.user_repository.get_by_id(user_id)

        if user is None:
            raise NotFoundException("User")

        role = self.role_repository.get_by_id(role_id)

        if role is None:
            raise NotFoundException("Role")

        assignment = self.repository.get_by_user_and_role(
            user_id=user_id,
            role_id=role_id,
        )

        if assignment is not None:
            raise ConflictException(
                "Role already assigned."
            )

        self.repository.create(
            UserRole(
                user_id=user_id,
                role_id=role_id,
            )
        )

        self.repository.commit()

    def remove_role(
        self,
        user_id: int,
        role_id: int,
    ) -> None:

        assignment = self.repository.get_by_user_and_role(
            user_id=user_id,
            role_id=role_id,
        )

        if assignment is None:
            raise NotFoundException(
                "User role assignment"
            )

        self.repository.delete(
            assignment
        )

        self.repository.commit()

    def get_roles(
        self,
        user_id: int,
    ) -> list:

        user = self.user_repository.get_by_id(user_id)

        if user is None:
            raise NotFoundException("User")

        assignments = self.repository.get_by_user_id(
            user_id,
        )

        return [
            assignment.role
            for assignment in assignments
        ]
