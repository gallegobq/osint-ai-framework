from typing import Annotated

from fastapi import APIRouter, Depends, Form, status
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

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    credentials: LoginRequest,
    auth_service: Annotated[
        AuthenticationService,
        Depends(get_auth_service),
    ],
) -> TokenResponse:

    """
    Autentica un usuario mediante credenciales
    en formato JSON.
    
    Genera un Access Token y un Refresh Token,
    registrando una nueva sesión activa.
    """

    return auth_service.login(credentials)


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
    request: RefreshTokenRequest,
    auth_session_service: Annotated[
        AuthSessionService,
        Depends(get_auth_session_service),
    ],
) -> TokenResponse:
    """
    Refresh Token Rotation.
    """

    return auth_session_service.refresh(request)


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout_all(
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
