from datetime import datetime, timezone

from app.auth.totp import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    provisioning_uri,
    verify_totp,
)
from app.core.exceptions import BadRequestException, ConflictException
from app.core.security import verify_password
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.mfa import (
    MfaDisableRequest,
    MfaSetupRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
)
from app.services.audit_service import AuditService
from app.services.session_service import SessionService


class MfaService:
    def __init__(
        self,
        users: UserRepository,
        sessions: SessionService,
        audit: AuditService,
    ):
        self.users = users
        self.sessions = sessions
        self.audit = audit

    def setup(self, user: User, request: MfaSetupRequest) -> MfaSetupResponse:
        if user.mfa_enabled:
            raise ConflictException("MFA is already enabled.")
        if not verify_password(request.password, user.hashed_password):
            self._record(user, "auth.mfa.setup.denied")
            self.users.commit()
            raise BadRequestException("Password is invalid.")
        secret = generate_totp_secret()
        user.mfa_secret = encrypt_totp_secret(secret)
        user.mfa_confirmed_at = None
        self._record(user, "auth.mfa.setup.started")
        self.users.commit()
        return MfaSetupResponse(
            secret=secret,
            provisioning_uri=provisioning_uri(user.username, secret),
        )

    def confirm(self, user: User, request: MfaVerifyRequest) -> None:
        if not user.mfa_secret:
            raise BadRequestException("Start MFA setup before confirmation.")
        if not verify_totp(decrypt_totp_secret(user.mfa_secret), request.code):
            self._record(user, "auth.mfa.confirm.denied")
            self.users.commit()
            raise BadRequestException("Invalid MFA verification code.")
        user.mfa_enabled = True
        user.mfa_confirmed_at = datetime.now(timezone.utc)
        self.sessions.revoke_all_sessions(user.id, commit=False)
        self._record(user, "auth.mfa.enabled")
        self.users.commit()

    def disable(self, user: User, request: MfaDisableRequest) -> None:
        if not user.mfa_enabled or not user.mfa_secret:
            raise BadRequestException("MFA is not enabled.")
        if not verify_password(request.password, user.hashed_password):
            self._record(user, "auth.mfa.disable.denied")
            self.users.commit()
            raise BadRequestException("Password or MFA code is invalid.")
        if not verify_totp(decrypt_totp_secret(user.mfa_secret), request.code):
            self._record(user, "auth.mfa.disable.denied")
            self.users.commit()
            raise BadRequestException("Password or MFA code is invalid.")
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_confirmed_at = None
        self.sessions.revoke_all_sessions(user.id, commit=False)
        self._record(user, "auth.mfa.disabled")
        self.users.commit()

    def _record(self, user: User, action: str) -> None:
        self.audit.record(
            actor_user_id=user.id,
            action=action,
            resource_type="user",
            resource_id=user.id,
        )
