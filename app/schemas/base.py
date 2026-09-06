from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    """
    Clase base para todos los schemas.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )
