from fastapi import HTTPException, status


class AppException(HTTPException):
    """
    Excepción base del framework.
    Todas las excepciones personalizadas deben heredar de esta clase.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
    ):
        self.code = code

        super().__init__(
            status_code=status_code,
            detail={
                "code": code,
                "message": message,
            },
        )


# ============================================================
# 400 Bad Request
# ============================================================

class BadRequestException(AppException):

    def __init__(self, message: str):

        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="BAD_REQUEST",
            message=message,
        )


# ============================================================
# 401 Unauthorized
# ============================================================

class UnauthorizedException(AppException):

    def __init__(self):

        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="UNAUTHORIZED",
            message="Authentication required.",
        )


class InvalidCredentialsException(AppException):

    def __init__(self):

        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_CREDENTIALS",
            message="Invalid username or password.",
        )


class MfaRequiredException(AppException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="MFA_REQUIRED",
            message="A current MFA code is required.",
        )


class InvalidTokenException(AppException):

    def __init__(self):

        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_TOKEN",
            message="Invalid or expired token.",
        )


# ============================================================
# 403 Forbidden
# ============================================================

class ForbiddenException(AppException):

    def __init__(self):

        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            code="FORBIDDEN",
            message="Permission denied.",
        )


# ============================================================
# 404 Not Found
# ============================================================

class NotFoundException(AppException):

    def __init__(self, resource: str):

        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            code="NOT_FOUND",
            message=f"{resource} not found.",
        )


# ============================================================
# 409 Conflict
# ============================================================

class ConflictException(AppException):

    def __init__(self, message: str):

        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            code="CONFLICT",
            message=message,
        )


class EmailAlreadyExistsException(ConflictException):

    def __init__(self):

        super().__init__(
            "Email already registered."
        )


class UsernameAlreadyExistsException(ConflictException):

    def __init__(self):

        super().__init__(
            "Username already registered."
        )

class RefreshTokenReuseException(AppException):
    """
    Se detectó la reutilización de un Refresh Token
    perteneciente a una sesión previamente revocada.
    """

    def __init__(self):

        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="REFRESH_TOKEN_REUSE",
            message="Refresh token reuse detected.",
        )


class ServiceUnavailableException(AppException):
    def __init__(self, message: str = "Service temporarily unavailable."):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="SERVICE_UNAVAILABLE",
            message=message,
        )
