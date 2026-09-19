from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Form, Header, Response, status
from fastapi.security import OAuth2PasswordRequestForm


from app.models.user_session import UserSession
from app.auth.dependencies import (
    get_current_user,
    get_current_session,
)
from app.auth.schemas import (
    CurrentUserResponse,
    LoginRequest,
    RefreshTokenRequest,
    SessionResponse,
    TokenResponse,
)
from app.auth.service import AuthenticationService
from app.dependencies.auth import get_auth_service, get_mfa_service
from app.dependencies.auth_session import (
    get_auth_session_service,
)
from app.models.user import User
from app.services.auth_session_service import (
    AuthSessionService,
)
from app.schemas.mfa import MfaDisableRequest, MfaSetupResponse, MfaVerifyRequest
from app.services.mfa_service import MfaService
from app.core.exceptions import InvalidCredentialsException
from app.core.settings import settings

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        max_age=settings.refresh_token_expire_days * 86_400,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api/v1/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.auth_cookie_name,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api/v1/auth",
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    credentials: LoginRequest,
    response: Response,
    auth_service: Annotated[
        AuthenticationService,
        Depends(get_auth_service),
    ],
    refresh_transport: Annotated[
        str | None, Header(alias="X-Refresh-Token-Transport")
    ] = None,
) -> TokenResponse:

    """
    Autentica un usuario mediante credenciales
    en formato JSON.
    
    Genera un Access Token y un Refresh Token,
    registrando una nueva sesión activa.
    """

    tokens = auth_service.login(credentials)
    if refresh_transport == "cookie" and tokens.refresh_token:
        _set_refresh_cookie(response, tokens.refresh_token)
        return tokens.model_copy(update={"refresh_token": None})
    return tokens


@router.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
def oauth2_login(
    form_data: Annotated[
        OAuth2PasswordRequestForm,
        Depends(),
    ],
    auth_service: Annotated[
        AuthenticationService,
        Depends(get_auth_service),
    ],
    mfa_code: Annotated[str | None, Form(pattern=r"^[0-9]{6}$")] = None,
) -> TokenResponse:
    """
    Endpoint OAuth2 compatible con Swagger.
    """

    credentials = LoginRequest(
        username=form_data.username,
        password=form_data.password,
        mfa_code=mfa_code,
    )

    return auth_service.login(credentials)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
def refresh(
    response: Response,
    auth_session_service: Annotated[
        AuthSessionService,
        Depends(get_auth_session_service),
    ],
    request: RefreshTokenRequest | None = None,
    refresh_cookie: Annotated[
        str | None, Cookie(alias=settings.auth_cookie_name)
    ] = None,
    refresh_transport: Annotated[
        str | None, Header(alias="X-Refresh-Token-Transport")
    ] = None,
) -> TokenResponse:
    """
    Refresh Token Rotation.
    """

    supplied_token = request.refresh_token if request is not None else refresh_cookie
    if not supplied_token:
        raise InvalidCredentialsException()
    tokens = auth_session_service.refresh(
        RefreshTokenRequest(refresh_token=supplied_token)
    )
    if refresh_transport == "cookie" or request is None:
        if not tokens.refresh_token:
            raise InvalidCredentialsException()
        _set_refresh_cookie(response, tokens.refresh_token)
        return tokens.model_copy(update={"refresh_token": None})
    return tokens


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout_all(
    response: Response,
    current_user: Annotated[
        User,
        Depends(get_current_user),
    ],
    auth_session_service: Annotated[
        AuthSessionService,
        Depends(get_auth_session_service),
    ],
) -> None:
    """
    Revoca todas las sesiones activas del usuario.
    """

    auth_session_service.logout_all(
        current_user,
    )
    _clear_refresh_cookie(response)

@router.get(
    "/me",
    response_model=CurrentUserResponse,
)
def me(
    current_user: Annotated[
        User,
        Depends(get_current_user),
    ],
) -> CurrentUserResponse:
    """
    Devuelve el usuario autenticado.
    """

    return CurrentUserResponse.model_validate(
        current_user,
    )

@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(
    response: Response,
    current_session: Annotated[
        UserSession,
        Depends(get_current_session),
    ],
    auth_session_service: Annotated[
        AuthSessionService,
        Depends(get_auth_session_service),
    ],
) -> None:

    auth_session_service.logout(
        current_session,
    )
    _clear_refresh_cookie(response)


@router.get(
    "/sessions",
    response_model=list[SessionResponse],
)
def list_sessions(
    current_user: Annotated[
        User,
        Depends(get_current_user),
    ],
    auth_session_service: Annotated[
        AuthSessionService,
        Depends(get_auth_session_service),
    ],
) -> list[SessionResponse]:
    return [
        SessionResponse.model_validate(session)
        for session in auth_session_service.list_sessions(current_user)
    ]


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_session(
    session_id: int,
    current_user: Annotated[
        User,
        Depends(get_current_user),
    ],
    auth_session_service: Annotated[
        AuthSessionService,
        Depends(get_auth_session_service),
    ],
) -> None:
    auth_session_service.revoke_user_session(current_user, session_id)


@router.post("/mfa/setup", response_model=MfaSetupResponse)
def setup_mfa(
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[MfaService, Depends(get_mfa_service)],
) -> MfaSetupResponse:
    return service.setup(current_user)


@router.post("/mfa/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_mfa(
    request: MfaVerifyRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[MfaService, Depends(get_mfa_service)],
) -> None:
    service.confirm(current_user, request)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_mfa(
    request: MfaDisableRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[MfaService, Depends(get_mfa_service)],
) -> None:
    service.disable(current_user, request)
