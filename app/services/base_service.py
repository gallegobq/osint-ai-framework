from typing import Generic, TypeVar

from pydantic import BaseModel


SchemaType = TypeVar(
    "SchemaType",
    bound=BaseModel,
)


class BaseService(Generic[SchemaType]):
    """
    Clase base para todos los servicios.

    Proporciona métodos comunes para convertir
    modelos SQLAlchemy a Schemas Pydantic.
    """

    @staticmethod
    def to_schema(
        schema: type[SchemaType],
        obj,
    ) -> SchemaType:
        """
        Convierte un modelo ORM en un Schema.
        """

        return schema.model_validate(obj)

    @staticmethod
    def to_schema_list(
        schema: type[SchemaType],
        objects: list,
    ) -> list[SchemaType]:
        """
        Convierte una lista de modelos ORM.
        """

        return [
            schema.model_validate(item)
            for item in objects
        ]
