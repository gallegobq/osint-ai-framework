from datetime import datetime, timedelta, timezone

from app.core.exceptions import (
    InvalidCredentialsException,
    RefreshTokenReuseException,
)

from app.core.security import hash_password
from app.core.settings import settings

from app.models.user import User
from app.models.user_session import UserSession
from app.repositories.user_session_repository import UserSessionRepository
from app.core.security import verify_password

class SessionService:
    """
    Servicio encargado de administrar las
    sesiones de autenticación.
    """

    def __init__(
        self,
        repository: UserSessionRepository,
    ):
        self.repository = repository

    def create_session(
        self,
        user: User,
        refresh_token: str,
        jti: str,
        access_jti: str,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> UserSession:
        """
        Crea una nueva sesión.
        """

        now = datetime.now(timezone.utc)

        session = UserSession(
            user_id=user.id,
            jti=jti,
            refresh_token_hash=hash_password(
                refresh_token,
            ),
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
            last_used_at=now,
            expires_at=now + timedelta(
                days=settings.refresh_token_expire_days,
            ),
            access_jti=access_jti
        )

        self.repository.create(session)
        self.repository.commit()

        return session

    def update_last_used(
        self,
        session: UserSession,
    ) -> None:
        """
        Actualiza la fecha del último uso.
        """

        session.last_used_at = datetime.now(
            timezone.utc,
        )

        self.repository.commit()

    def revoke_session(
        self,
        session: UserSession,
        *,
        commit: bool = True,
    ) -> None:
        """
        Revoca una sesión.
        """

        self.repository.revoke(
            session,
        )

        if commit:
            self.repository.commit()

    def revoke_all_sessions(
        self,
        user_id: int,
        *,
        commit: bool = True,
    ) -> None:
        """
        Revoca todas las sesiones
        activas del usuario.
        """

        self.repository.revoke_all(
            user_id,
        )

        if commit:
            self.repository.commit()

    def get_user_sessions(
        self,
        user_id: int,
    ) -> list[UserSession]:
        """
        Obtiene todas las sesiones
        activas de un usuario.
        """

        return self.repository.get_user_sessions(
            user_id,
        )

    def revoke_owned_session(
        self,
        user_id: int,
        session_id: int,
    ) -> None:
        session = self.repository.get_by_id(session_id)
        if session is None or session.user_id != user_id:
            raise InvalidCredentialsException()
        self.revoke_session(session)

    def verify_refresh_token(
        self,
        session: UserSession,
        refresh_token: str,
    ) -> None:
        """
        Verifica que el Refresh Token recibido
        corresponda al almacenado.
        """
    
        if not verify_password(
            refresh_token,
            session.refresh_token_hash,
        ):
            raise InvalidCredentialsException()


    def get_valid_session(
        self,
        jti: str,
    ) -> UserSession:
        """
        Obtiene una sesión válida a partir de su JTI.
    
        - Si no existe → InvalidCredentialsException.
        - Si está revocada → RefreshTokenReuseException.
        - Si está activa → devuelve la sesión.
        """
    
        session = self.repository.get_by_jti(
            jti,
        )
    
        if session is None:
            raise InvalidCredentialsException()
    
        if session.revoked_at is not None:
            self.repository.revoke_all(session.user_id)
            self.repository.commit()
            raise RefreshTokenReuseException()

        if session.expires_at <= datetime.now(timezone.utc):
            self.repository.revoke(session)
            self.repository.commit()
            raise InvalidCredentialsException()
    
        return session

    def get_active_session_by_access_jti(
        self,
        access_jti: str,
    ) -> UserSession:
        """
        Valida que el Access Token pertenezca
        a una sesión activa.
        """
    
        session = self.repository.get_active_session_by_access_jti(
            access_jti,
        )
    
        if session is None:
            raise InvalidCredentialsException()

        if session.expires_at <= datetime.now(timezone.utc):
            raise InvalidCredentialsException()

        return session
