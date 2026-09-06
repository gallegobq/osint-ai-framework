from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import EmailStr
from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator


USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]+$"


class UserCreate(BaseModel):
    """
    Datos requeridos para crear un usuario.

    La contraseña se recibe únicamente como texto plano en la entrada.
    Nunca debe incluirse en modelos de respuesta ni persistirse sin hash.
    """

    username: str = Field(
        min_length=3,
        max_length=50,
        pattern=USERNAME_PATTERN,
    )

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        """
        Normalize surrounding whitespace without silently changing case.

        Case normalization must remain aligned with repository uniqueness
        rules and database constraints.
        """
        return value.strip()

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        """
        Normalize email addresses for deterministic uniqueness checks.
        """
        return str(value).strip().lower()


class UserUpdate(BaseModel):
    """
    Campos administrativos permitidos para actualización parcial.

    Estado, credenciales, roles and superuser privileges are intentionally
    excluded because they require dedicated use cases and permissions.
    """

    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
        pattern=USERNAME_PATTERN,
    )

    email: EmailStr | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(
        cls,
        data: object,
    ) -> object:
        if not isinstance(data, dict):
            return data

        nullable_fields = {
            field_name
            for field_name in ("username", "email")
            if field_name in data and data[field_name] is None
        }

        if nullable_fields:
            fields = ", ".join(sorted(nullable_fields))
            raise ValueError(
                f"The following fields cannot be null: {fields}."
            )

        return data


    @field_validator("username")
    @classmethod
    def normalize_optional_username(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return value.strip()

    @field_validator("email")
    @classmethod
    def normalize_optional_email(
        cls,
        value: EmailStr | None,
    ) -> str | None:
        if value is None:
            return None

        return str(value).strip().lower()

    @model_validator(mode="after")
    def validate_at_least_one_field(self) -> "UserUpdate":
        """
        Reject empty PATCH payloads.

        An empty update would generate a successful request without producing
        any state change or meaningful audit event.
        """
        if not self.model_fields_set:
            raise ValueError(
                "At least one field must be provided."
            )

        return self


class UserChangePassword(BaseModel):
    """
    Payload for an authenticated user changing their own password.
    """

    current_password: str = Field(
        min_length=1,
        max_length=128,
    )

    new_password: str = Field(
        min_length=8,
        max_length=128,
    )

    @model_validator(mode="after")
    def validate_password_change(self) -> "UserChangePassword":
        if self.current_password == self.new_password:
            raise ValueError(
                "The new password must be different "
                "from the current password."
            )

        return self


class UserResetPassword(BaseModel):
    """
    Payload for an administrative password reset.
    """

    new_password: str = Field(
        min_length=8,
        max_length=128,
    )


class UserRead(BaseModel):
    """
    Administrative representation of a user.

    Passwords, password hashes and session credentials are never exposed.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int

    username: str

    email: EmailStr

    is_active: bool

    is_superuser: bool

    password_changed_at: datetime

    deleted_at: datetime | None

    created_at: datetime

    updated_at: datetime
