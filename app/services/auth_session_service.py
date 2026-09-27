from jwt.exceptions import InvalidTokenError

from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_token_type,
)
from app.auth.schemas import (
    RefreshTokenRequest,
    TokenResponse,
)
from app.core.exceptions import (
    InvalidCredentialsException,
)
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.session_service import SessionService

from app.models.user import User
from app.models.user_session import UserSession

class AuthSessionService:
    """
    Servicio encargado de administrar
    las sesiones autenticadas.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        session_service: SessionService,
        audit_service: AuditService,
    ):
        self.user_repository = user_repository
        self.session_service = session_service
        self.audit = audit_service

    def refresh(
        self,
        request: RefreshTokenRequest,
    ) -> TokenResponse:
        """
        Realiza Refresh Token Rotation.
        """

        try:
            payload = decode_token(
                request.refresh_token,
            )

            validate_token_type(
                payload,
                "refresh",
            )

        except InvalidTokenError:
            raise InvalidCredentialsException()

        refresh_jti = payload.get("jti")
        subject = payload.get("sub")

        if not isinstance(refresh_jti, str) or subject is None:
            raise InvalidCredentialsException()

        session = self.session_service.get_valid_session(
            refresh_jti,
        )

        try:
            user_id = int(subject)
        except (TypeError, ValueError) as exc:
            raise InvalidCredentialsException() from exc

        if session.user_id != user_id:
            raise InvalidCredentialsException()

        self.session_service.verify_refresh_token(
            session,
            request.refresh_token,
        )

        user = self.user_repository.get_by_id(
            user_id,
        )

        if (
            user is None
            or not user.is_active
            or user.deleted_at is not None
        ):
            raise InvalidCredentialsException()

        #
        # Revocar la sesión anterior
        #
        self.session_service.revoke_session(session, commit=False)

        #
        # Crear nuevo Refresh Token
        #
        refresh_token, refresh_jti = create_refresh_token(
            str(user.id),
        )

        access_token, access_jti = create_access_token(
                    str(user.id),
                )
        
        new_session = self.session_service.create_session(
            user=user,
            refresh_token=refresh_token,
            jti=refresh_jti,
            access_jti=access_jti,
            device_name=session.device_name,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            commit=False,
        )
        self.audit.record(
            actor_user_id=user.id,
            action="auth.session.rotated",
            resource_type="user_session",
            resource_id=new_session.id,
            data={"previous_session_id": session.id},
        )
        self.session_service.repository.commit()
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def logout(
        self,
        session: UserSession,
    ) -> None:
        """
        Revoca una sesión.
        """

        self.session_service.revoke_session(session, commit=False)
        self.audit.record(
            actor_user_id=session.user_id,
            action="auth.logout",
            resource_type="user_session",
            resource_id=session.id,
        )
        self.session_service.repository.commit()

    def logout_all(
        self,
        user: User,
    ) -> None:
        """
        Revoca todas las sesiones
        del usuario.
        """

        self.session_service.revoke_all_sessions(user.id, commit=False)
        self.audit.record(
            actor_user_id=user.id,
            action="auth.sessions.revoked_all",
            resource_type="user",
            resource_id=user.id,
        )
        self.session_service.repository.commit()

    def list_sessions(
        self,
        user: User,
    ) -> list[UserSession]:
        """
        Lista las sesiones activas
        del usuario.
        """

        return self.session_service.get_user_sessions(
            user.id,
        )

    def revoke_user_session(
        self,
        user: User,
        session_id: int,
    ) -> None:
        session = self.session_service.get_owned_session(user.id, session_id)
        self.session_service.revoke_session(session, commit=False)
        self.audit.record(
            actor_user_id=user.id,
            action="auth.session.revoked",
            resource_type="user_session",
            resource_id=session.id,
        )
        self.session_service.repository.commit()
