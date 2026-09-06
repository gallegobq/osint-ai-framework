from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.role import Role
from app.repositories.base_repository import BaseRepository


class RoleRepository(BaseRepository[Role]):
    """
    Acceso a datos para la entidad Role.
    """

    def __init__(self, db: Session):
        super().__init__(Role, db)

    def get_by_name(
        self,
        name: str,
    ) -> Role | None:
        """
        Obtiene un rol por su nombre exacto.
        """

        stmt = select(Role).where(
            Role.name == name
        )

        return self.db.scalar(stmt)
