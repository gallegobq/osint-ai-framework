from pydantic import BaseModel, Field


class UserRoleAssign(BaseModel):
    """
    Solicitud para asignar un rol a un usuario.
    """

    role_id: int = Field(
        gt=0,
        description="ID del rol a asignar.",
    )
