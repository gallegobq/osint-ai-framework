from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
)

from app.auth.schemas import (
    LoginRequest,
    TokenResponse,
)

from app.core.exceptions import InvalidCredentialsException
from app.core.security import verify_password

from app.repositories.user_repository import UserRepository
from app.services.session_service import SessionService
from app.auth.totp import decrypt_totp_secret, verify_totp
from app.core.exceptions import MfaRequiredException

class AuthenticationService:
    """
    Servicio encargado de la autenticación.
    """

    def __init__(
            self,
            repository: UserRepository,
            session_service: SessionService,
        ):
            self.repository = repository
            self.session_service = session_service

    def login(
        self,
        credentials: LoginRequest,
    ) -> TokenResponse:
        """
        Autentica un usuario y genera
        Access y Refresh Tokens.
        """

        user = self.repository.get_by_username(
            credentials.username
        )

        if user is None:
            raise InvalidCredentialsException()

        if not user.is_active or user.deleted_at is not None:
            raise InvalidCredentialsException()

        if not verify_password(
            credentials.password,
            user.hashed_password,
        ):
            raise InvalidCredentialsException()

        if user.mfa_enabled:
            if not credentials.mfa_code:
                raise MfaRequiredException()
            if not user.mfa_secret or not verify_totp(
                decrypt_totp_secret(user.mfa_secret), credentials.mfa_code
            ):
                raise InvalidCredentialsException()

        refresh_token, refresh_jti = create_refresh_token(
            str(user.id),
        )
        
        access_token, access_jti = create_access_token(
            str(user.id),
        )
        
        self.session_service.create_session(
            user=user,
            refresh_token=refresh_token,
            jti=refresh_jti,
            access_jti=access_jti,
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )
