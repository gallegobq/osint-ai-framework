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
from app.services.audit_service import AuditService
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
            audit_service: AuditService,
        ):
            self.repository = repository
            self.session_service = session_service
            self.audit = audit_service

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
            self._record_failed_login(None, "unknown_identity")
            raise InvalidCredentialsException()

        if not user.is_active or user.deleted_at is not None:
            self._record_failed_login(user.id, "inactive_identity")
            raise InvalidCredentialsException()

        if not verify_password(
            credentials.password,
            user.hashed_password,
        ):
            self._record_failed_login(user.id, "invalid_credentials")
            raise InvalidCredentialsException()

        if user.mfa_enabled:
            if not credentials.mfa_code:
                self._record_failed_login(user.id, "mfa_required")
                raise MfaRequiredException()
            if not user.mfa_secret or not verify_totp(
                decrypt_totp_secret(user.mfa_secret), credentials.mfa_code
            ):
                self._record_failed_login(user.id, "invalid_mfa")
                raise InvalidCredentialsException()

        refresh_token, refresh_jti = create_refresh_token(
            str(user.id),
        )
        
        access_token, access_jti = create_access_token(
            str(user.id),
        )
        
        self.audit.record(
            actor_user_id=user.id,
            action="auth.login.succeeded",
            resource_type="user",
            resource_id=user.id,
            data={"mfa_used": bool(user.mfa_enabled)},
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

    def _record_failed_login(self, user_id: int | None, reason: str) -> None:
        self.audit.record(
            actor_user_id=None,
            action="auth.login.failed",
            resource_type="user",
            resource_id=user_id if user_id is not None else "unknown",
            data={"reason": reason},
        )
        self.repository.commit()
