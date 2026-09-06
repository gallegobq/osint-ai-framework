from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    """
    Credenciales para autenticación.
    """

    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)
    mfa_code: str | None = Field(default=None, pattern=r"^[0-9]{6}$")


class RefreshTokenRequest(BaseModel):
    """
    Solicitud para renovar un Refresh Token.
    """

    refresh_token: str = Field(min_length=1, max_length=4096)


class TokenResponse(BaseModel):
    """
    Respuesta de autenticación.

    Se utiliza tanto para Login como para Refresh.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)


class CurrentUserResponse(BaseModel):
    """
    Usuario autenticado.
    """

    id: int
    username: str
    email: str
    mfa_enabled: bool

    model_config = ConfigDict(from_attributes=True)


class SessionResponse(BaseModel):
    """Safe session metadata; token material and hashes are excluded."""

    id: int
    device_name: str | None
    ip_address: str | None
    user_agent: str | None
    last_used_at: datetime
    expires_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
