from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.permission import Permission
from app.repositories.base_repository import BaseRepository


class PermissionRepository(BaseRepository[Permission]):
    """
    Acceso a datos para la entidad Permission.
    """

    def __init__(self, db: Session):
        super().__init__(Permission, db)

    def get_by_code(
        self,
        code: str,
    ) -> Permission | None:
        """
        Obtiene un permiso por su código único.
        """

        stmt = select(Permission).where(
            Permission.code == code
        )

        return self.db.scalar(stmt)

    def get_by_resource_and_action(
        self,
        resource: str,
        action: str,
    ) -> Permission | None:
        """
        Obtiene un permiso por recurso y acción.
        """

        stmt = select(Permission).where(
            Permission.resource == resource,
            Permission.action == action,
        )

        return self.db.scalar(stmt)
