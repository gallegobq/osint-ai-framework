from datetime import datetime
from enum import StrEnum

from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator

from app.schemas.base import BaseSchema
from app.schemas.user import UserRead


class UserSortField(StrEnum):
    """
    Campos permitidos para ordenar consultas de usuarios.

    Esta lista blanca evita utilizar directamente nombres de columnas
    recibidos desde el cliente.
    """

    ID = "id"
    USERNAME = "username"
    EMAIL = "email"
    IS_ACTIVE = "is_active"
    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"
    PASSWORD_CHANGED_AT = "password_changed_at"
    DELETED_AT = "deleted_at"


class SortOrder(StrEnum):
    """
    Direcciones de ordenamiento admitidas.
    """

    ASC = "asc"
    DESC = "desc"


class UserListQuery(BaseSchema):
    """
    Parámetros admitidos para listar usuarios.

    Este esquema representa únicamente criterios de consulta. La autorización
    para incluir usuarios eliminados se validará posteriormente en el servicio
    o en la dependencia del endpoint.
    """

    page: int = Field(
        default=1,
        ge=1,
        description="Número de página, comenzando en 1.",
    )

    page_size: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Cantidad máxima de usuarios por página.",
    )

    search: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description=(
            "Texto de búsqueda sobre username y email."
        ),
    )

    is_active: bool | None = Field(
        default=None,
        description="Filtrar por estado activo o inactivo.",
    )

    is_deleted: bool | None = Field(
        default=False,
        description=(
            "Incluir exclusivamente usuarios eliminados o no eliminados. "
            "Requiere permiso adicional para consultar eliminados."
        ),
    )

    role_id: int | None = Field(
        default=None,
        ge=1,
        description="Filtrar usuarios asignados a un rol determinado.",
    )

    created_from: datetime | None = Field(
        default=None,
        description="Fecha mínima de creación, inclusive.",
    )

    created_to: datetime | None = Field(
        default=None,
        description="Fecha máxima de creación, inclusive.",
    )

    sort_by: UserSortField = Field(
        default=UserSortField.CREATED_AT,
        description="Campo permitido para ordenamiento.",
    )

    sort_order: SortOrder = Field(
        default=SortOrder.DESC,
        description="Dirección del ordenamiento.",
    )

    @field_validator("search")
    @classmethod
    def normalize_search(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized_value = value.strip()

        if not normalized_value:
            raise ValueError(
                "Search cannot contain only whitespace."
            )

        return normalized_value

    @model_validator(mode="after")
    def validate_date_range(self) -> "UserListQuery":
        if (
            self.created_from is not None
            and self.created_to is not None
            and self.created_from > self.created_to
        ):
            raise ValueError(
                "created_from cannot be later than created_to."
            )

        return self

    @property
    def offset(self) -> int:
        """
        Calculate the SQL offset for offset-based pagination.
        """
        return (self.page - 1) * self.page_size


class PaginationMetadata(BaseSchema):
    """
    Metadatos de una respuesta paginada.
    """

    page: int = Field(
        ge=1,
    )

    page_size: int = Field(
        ge=1,
        le=100,
    )

    total_items: int = Field(
        ge=0,
    )

    total_pages: int = Field(
        ge=0,
    )

    has_previous: bool

    has_next: bool


class UserListResponse(BaseSchema):
    """
    Respuesta paginada del listado administrativo de usuarios.
    """

    items: list[UserRead]

    pagination: PaginationMetadata
