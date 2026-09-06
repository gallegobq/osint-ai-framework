from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class RoleCreate(BaseModel):
    """
    Datos requeridos para crear un rol.
    """

    name: str = Field(
        min_length=2,
        max_length=50,
    )

    description: str | None = Field(
        default=None,
        max_length=255,
    )


class RoleUpdate(BaseModel):
    """
    Datos permitidos para actualizar un rol.

    Todos los campos son opcionales para permitir
    actualizaciones parciales.
    """

    name: str | None = Field(
        default=None,
        min_length=2,
        max_length=50,
    )

    description: str | None = Field(
        default=None,
        max_length=255,
    )


class RoleRead(BaseModel):
    """
    Información pública de un rol.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int

    name: str

    description: str | None

    is_system: bool

    created_at: datetime

    updated_at: datetime
