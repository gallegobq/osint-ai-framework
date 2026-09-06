from app.core.exceptions import (
    ConflictException,
    NotFoundException,
)

from app.models.role_permission import RolePermission
from app.models.permission import Permission
from app.repositories.permission_repository import PermissionRepository
from app.repositories.role_permission_repository import (
    RolePermissionRepository,
)
from app.repositories.role_repository import RoleRepository


class RolePermissionService:
    """
    Administración de asignaciones Rol ↔ Permiso.
    """

    def __init__(
        self,
        role_repository: RoleRepository,
        permission_repository: PermissionRepository,
        repository: RolePermissionRepository,
    ):
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.repository = repository

    def assign_permission(
        self,
        role_id: int,
        permission_id: int,
    ) -> None:

        role = self.role_repository.get_by_id(role_id)

        if role is None:
            raise NotFoundException("Role")

        permission = self.permission_repository.get_by_id(
            permission_id
        )

        if permission is None:
            raise NotFoundException("Permission")

        assignment = (
            self.repository.get_by_role_and_permission(
                role_id=role_id,
                permission_id=permission_id,
            )
        )

        if assignment is not None:
            raise ConflictException(
                "Permission already assigned."
            )

        self.repository.create(
            RolePermission(
                role_id=role_id,
                permission_id=permission_id,
            )
        )

        self.repository.commit()

    def remove_permission(
        self,
        role_id: int,
        permission_id: int,
    ) -> None:

        assignment = (
            self.repository.get_by_role_and_permission(
                role_id=role_id,
                permission_id=permission_id,
            )
        )

        if assignment is None:
            raise NotFoundException(
                "Role permission assignment"
            )

        self.repository.delete(
            assignment
        )

        self.repository.commit()

    def get_permissions(
        self,
        role_id: int,
    ) -> list[Permission]:

        role = self.role_repository.get_by_id(
            role_id
        )

        if role is None:
            raise NotFoundException("Role")

        assignments = self.repository.get_by_role_id(
            role_id
        )

        return [
            assignment.permission
            for assignment in assignments
        ]
