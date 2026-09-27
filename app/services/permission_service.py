from sqlalchemy.exc import IntegrityError

from app.core.exceptions import (
    ConflictException,
    NotFoundException,
)

from app.models.permission import Permission

from app.repositories.permission_repository import (
    PermissionRepository,
)

from app.schemas.permission import (
    PermissionCreate,
    PermissionRead,
    PermissionUpdate,
)

from app.services.base_service import BaseService
from app.services.audit_service import AuditService


class PermissionService(BaseService[PermissionRead]):
    """
    Lógica de negocio para la administración de permisos.
    """

    def __init__(
        self,
        repository: PermissionRepository,
        audit: AuditService,
    ):
        self.repository = repository
        self.audit = audit

    def create_permission(
        self,
        data: PermissionCreate,
        actor_user_id: int,
    ) -> PermissionRead:

        if self.repository.get_by_code(data.code):
            raise ConflictException(
                "Permission already exists."
            )

        existing_mapping = (
            self.repository.get_by_resource_and_action(
                resource=data.resource,
                action=data.action,
            )
        )

        if existing_mapping is not None:
            raise ConflictException(
                "Permission resource and action already exist."
            )

        expected_code = (
            f"{data.resource}:{data.action}"
        )

        if data.code != expected_code:
            raise ConflictException(
                "Permission code must match resource and action."
            )

        permission = Permission(
            code=data.code,
            resource=data.resource,
            action=data.action,
            description=data.description,
            is_system=False,
        )

        try:

            self.repository.create(permission)
            self.audit.record(
                actor_user_id=actor_user_id,
                action="permissions.create",
                resource_type="permission",
                resource_id=permission.id,
                data={"code": permission.code},
            )
            self.repository.commit()

            return self.to_schema(
                PermissionRead,
                permission,
            )

        except IntegrityError:

            self.repository.rollback()

            raise ConflictException(
                "Database integrity error."
            )
        except Exception:
            self.repository.rollback()
            raise

    def get_permission(
        self,
        permission_id: int,
    ) -> PermissionRead:

        permission = self.repository.get_by_id(
            permission_id
        )

        if permission is None:
            raise NotFoundException(
                "Permission"
            )

        return self.to_schema(
            PermissionRead,
            permission,
        )

    def list_permissions(
        self,
    ) -> list[PermissionRead]:

        permissions = self.repository.get_all()

        return self.to_schema_list(
            PermissionRead,
            permissions,
        )

    def update_permission(
        self,
        permission_id: int,
        data: PermissionUpdate,
        actor_user_id: int,
    ) -> PermissionRead:

        permission = self.repository.get_by_id(
            permission_id
        )

        if permission is None:
            raise NotFoundException(
                "Permission"
            )

        if permission.is_system:
            raise ConflictException(
                "System permissions cannot be modified"
            )

        if data.description is not None:
            permission.description = (
                data.description
            )

        try:
            self.audit.record(
                actor_user_id=actor_user_id,
                action="permissions.update",
                resource_type="permission",
                resource_id=permission.id,
                data={
                    "code": permission.code,
                    "fields": sorted(data.model_fields_set),
                },
            )
            self.repository.commit()

            return self.to_schema(
                PermissionRead,
                permission,
            )

        except IntegrityError:

            self.repository.rollback()

            raise ConflictException(
                "Database integrity error."
            )
        except Exception:
            self.repository.rollback()
            raise

    def delete_permission(
        self,
        permission_id: int,
        actor_user_id: int,
    ) -> None:

        permission = self.repository.get_by_id(
            permission_id
        )

        if permission is None:
            raise NotFoundException(
                "Permission"
            )

        if permission.is_system:
            raise ConflictException(
                "System permissions cannot be deleted."
            )

        try:
            self.repository.delete(permission)
            self.audit.record(
                actor_user_id=actor_user_id,
                action="permissions.delete",
                resource_type="permission",
                resource_id=permission.id,
                data={"code": permission.code},
            )
            self.repository.commit()
        except IntegrityError as exc:
            self.repository.rollback()
            raise ConflictException(
                "Permission cannot be deleted because it is in use."
            ) from exc
        except Exception:
            self.repository.rollback()
            raise
