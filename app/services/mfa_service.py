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
from app.schemas.mfa import MfaDisableRequest, MfaSetupResponse, MfaVerifyRequest
from app.services.session_service import SessionService


class MfaService:
    def __init__(
        self,
        users: UserRepository,
        sessions: SessionService,
    ):
        self.users = users
        self.sessions = sessions

    def setup(self, user: User) -> MfaSetupResponse:
        if user.mfa_enabled:
            raise ConflictException("MFA is already enabled.")
        secret = generate_totp_secret()
        user.mfa_secret = encrypt_totp_secret(secret)
        user.mfa_confirmed_at = None
        self.users.commit()
        return MfaSetupResponse(
            secret=secret,
            provisioning_uri=provisioning_uri(user.username, secret),
        )

    def confirm(self, user: User, request: MfaVerifyRequest) -> None:
        if not user.mfa_secret:
            raise BadRequestException("Start MFA setup before confirmation.")
        if not verify_totp(decrypt_totp_secret(user.mfa_secret), request.code):
            raise BadRequestException("Invalid MFA verification code.")
        user.mfa_enabled = True
        user.mfa_confirmed_at = datetime.now(timezone.utc)
        self.users.commit()

    def disable(self, user: User, request: MfaDisableRequest) -> None:
        if not user.mfa_enabled or not user.mfa_secret:
            raise BadRequestException("MFA is not enabled.")
        if not verify_password(request.password, user.hashed_password):
            raise BadRequestException("Password or MFA code is invalid.")
        if not verify_totp(decrypt_totp_secret(user.mfa_secret), request.code):
            raise BadRequestException("Password or MFA code is invalid.")
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_confirmed_at = None
        self.sessions.revoke_all_sessions(user.id, commit=False)
        self.users.commit()
