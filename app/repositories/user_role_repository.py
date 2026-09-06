from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user_role import UserRole
from app.repositories.base_repository import BaseRepository


class UserRoleRepository(BaseRepository[UserRole]):
    """
    Acceso a datos para las asignaciones entre usuarios y roles.
    """

    def __init__(self, db: Session):
        super().__init__(UserRole, db)

    def get_by_user_and_role(
        self,
        user_id: int,
        role_id: int,
    ) -> UserRole | None:
        """
        Obtiene una asignación específica entre usuario y rol.
        """

        stmt = select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )

        return self.db.scalar(stmt)

    def get_by_user_id(
        self,
        user_id: int,
    ) -> list[UserRole]:
        """
        Obtiene todas las asignaciones de roles de un usuario.
        """

        stmt = select(UserRole).where(
            UserRole.user_id == user_id
        )

        return list(
            self.db.scalars(stmt).all()
        )

    def get_by_role_id(
        self,
        role_id: int,
    ) -> list[UserRole]:
        """
        Obtiene todas las asignaciones de usuarios de un rol.
        """

        stmt = select(UserRole).where(
            UserRole.role_id == role_id
        )

        return list(
            self.db.scalars(stmt).all()
        )
