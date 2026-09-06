from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user_session import UserSession
from app.repositories.base_repository import BaseRepository


class UserSessionRepository(BaseRepository[UserSession]):
    """
    Repositorio para la gestión de sesiones
    de autenticación.
    """

    def __init__(
        self,
        db: Session,
    ):
        super().__init__(
            UserSession,
            db,
        )

    def get_by_jti(
        self,
        jti: str,
    ) -> UserSession | None:
        """
        Obtiene una sesión por su JTI.
        """

        stmt = select(UserSession).where(
            UserSession.jti == jti,
        )

        return self.db.scalar(stmt)
    
    def get_user_sessions(
        self,
        user_id: int,
    ) -> list[UserSession]:
        """
        Devuelve todas las sesiones activas
        de un usuario.
        """

        stmt = (
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
            )
            .order_by(UserSession.created_at.desc())
        )

        return list(self.db.scalars(stmt).all())

    def revoke(
        self,
        session: UserSession,
    ) -> None:
        """
        Revoca una sesión.
        """

        session.revoked_at = datetime.now(
            timezone.utc,
        )

        self.db.flush()

    def revoke_all(
        self,
        user_id: int,
    ) -> None:
        """
        Revoca todas las sesiones activas
        del usuario.
        """

        sessions = self.get_user_sessions(
            user_id,
        )

        now = datetime.now(
            timezone.utc,
        )

        for session in sessions:
            session.revoked_at = now

        self.db.flush()

    def get_active_session_by_access_jti(
        self,
        access_jti: str,
    ) -> UserSession | None:
        """
        Obtiene una sesión activa mediante
        el JTI del Access Token.
        """
    
        stmt = select(UserSession).where(
            UserSession.access_jti == access_jti,
            UserSession.revoked_at.is_(None),
        )
    
        return self.db.scalar(stmt)
