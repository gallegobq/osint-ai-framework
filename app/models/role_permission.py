from sqlalchemy import ForeignKey
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from typing import TYPE_CHECKING

from app.models.base_model import BaseModel

if TYPE_CHECKING:
    from app.models.permission import Permission
    from app.models.role import Role


class RolePermission(BaseModel):
    """
    Relación entre roles y permisos.

    Se implementa como entidad independiente para permitir
    futuras extensiones como condiciones, alcance y auditoría.
    """

    __tablename__ = "role_permissions"

    __table_args__ = (
        UniqueConstraint(
            "role_id",
            "permission_id",
            name="uq_role_permissions_role_permission",
        ),
    )

    role_id: Mapped[int] = mapped_column(
        ForeignKey(
            "roles.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    permission_id: Mapped[int] = mapped_column(
        ForeignKey(
            "permissions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    role: Mapped["Role"] = relationship(
        "Role",
        back_populates="permission_assignments",
    )

    permission: Mapped["Permission"] = relationship(
        "Permission",
        back_populates="role_assignments",
    )
