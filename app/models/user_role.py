from sqlalchemy import ForeignKey
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from typing import TYPE_CHECKING

from app.models.base_model import BaseModel

if TYPE_CHECKING:
    from app.models.role import Role
    from app.models.user import User


class UserRole(BaseModel):
    """
    Relación entre usuarios y roles.

    Se implementa como entidad independiente para permitir
    futuras extensiones como expiración, alcance y auditoría.
    """

    __tablename__ = "user_roles"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "role_id",
            name="uq_user_roles_user_role",
        ),
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    role_id: Mapped[int] = mapped_column(
        ForeignKey(
            "roles.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="role_assignments",
    )

    role: Mapped["Role"] = relationship(
        "Role",
        back_populates="user_assignments",
    )
