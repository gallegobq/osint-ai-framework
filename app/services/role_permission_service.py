from sqlalchemy.exc import IntegrityError

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
from app.services.audit_service import AuditService


class RolePermissionService:
    """
    Administración de asignaciones Rol ↔ Permiso.
    """

    def __init__(
        self,
        role_repository: RoleRepository,
        permission_repository: PermissionRepository,
        repository: RolePermissionRepository,
        audit: AuditService,
    ):
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.repository = repository
        self.audit = audit

    def assign_permission(
        self,
        role_id: int,
        permission_id: int,
        actor_user_id: int,
    ) -> None:

        role = self.role_repository.get_by_id(role_id)

        if role is None:
            raise NotFoundException("Role")

        if role.is_system:
            raise ConflictException(
                "System role permissions cannot be modified."
            )

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

        try:
            self.repository.create(
                RolePermission(
                    role_id=role_id,
                    permission_id=permission_id,
                )
            )
            self.audit.record(
                actor_user_id=actor_user_id,
                action="roles.permissions.assign",
                resource_type="role",
                resource_id=role.id,
                data={
                    "role_name": role.name,
                    "permission_id": permission.id,
                    "permission_code": permission.code,
                },
            )
            self.repository.commit()
        except IntegrityError as exc:
            self.repository.rollback()
            raise ConflictException("Database integrity error.") from exc
        except Exception:
            self.repository.rollback()
            raise

    def remove_permission(
        self,
        role_id: int,
        permission_id: int,
        actor_user_id: int,
    ) -> None:

        role = self.role_repository.get_by_id(role_id)

        if role is None:
            raise NotFoundException("Role")

        if role.is_system:
            raise ConflictException(
                "System role permissions cannot be modified."
            )

        permission = self.permission_repository.get_by_id(permission_id)

        if permission is None:
            raise NotFoundException("Permission")

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

        try:
            self.repository.delete(assignment)
            self.audit.record(
                actor_user_id=actor_user_id,
                action="roles.permissions.remove",
                resource_type="role",
                resource_id=role.id,
                data={
                    "role_name": role.name,
                    "permission_id": permission.id,
                    "permission_code": permission.code,
                },
            )
            self.repository.commit()
        except IntegrityError as exc:
            self.repository.rollback()
            raise ConflictException("Database integrity error.") from exc
        except Exception:
            self.repository.rollback()
            raise

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
