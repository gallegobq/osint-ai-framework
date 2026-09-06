from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class PermissionCreate(BaseModel):
    """
    Datos requeridos para crear un permiso.
    """

    code: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$",
    )

    resource: str = Field(
        min_length=2,
        max_length=50,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )

    action: str = Field(
        min_length=2,
        max_length=50,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )

    description: str | None = Field(
        default=None,
        max_length=255,
    )


class PermissionUpdate(BaseModel):
    """
    Datos permitidos para actualizar un permiso.
    """

    description: str | None = Field(
        default=None,
        max_length=255,
    )


class PermissionRead(BaseModel):
    """
    Información pública de un permiso.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int

    code: str

    resource: str

    action: str

    description: str | None

    is_system: bool

    created_at: datetime

    updated_at: datetime
