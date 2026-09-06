from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.role_permission import RolePermission
from app.repositories.base_repository import BaseRepository


class RolePermissionRepository(BaseRepository[RolePermission]):
    """
    Acceso a datos para las asignaciones entre roles y permisos.
    """

    def __init__(self, db: Session):
        super().__init__(RolePermission, db)

    def get_by_role_and_permission(
        self,
        role_id: int,
        permission_id: int,
    ) -> RolePermission | None:
        """
        Obtiene una asignación específica entre rol y permiso.
        """

        stmt = select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
        )

        return self.db.scalar(stmt)

    def get_by_role_id(
        self,
        role_id: int,
    ) -> list[RolePermission]:
        """
        Obtiene todos los permisos asignados a un rol.
        """

        stmt = select(RolePermission).where(
            RolePermission.role_id == role_id
        )

        return list(
            self.db.scalars(stmt).all()
        )

    def get_by_permission_id(
        self,
        permission_id: int,
    ) -> list[RolePermission]:
        """
        Obtiene todos los roles que tienen un permiso específico.
        """

        stmt = select(RolePermission).where(
            RolePermission.permission_id == permission_id
        )

        return list(
            self.db.scalars(stmt).all()
        )
