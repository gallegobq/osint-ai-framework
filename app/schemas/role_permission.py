from pydantic import BaseModel, Field


class RolePermissionAssign(BaseModel):
    """
    Solicitud para asignar un permiso a un rol.
    """

    permission_id: int = Field(
        gt=0,
        description="ID del permiso que se asignará al rol.",
    )
