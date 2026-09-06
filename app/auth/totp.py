import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

from app.core.settings import settings


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _secret_bytes(secret: str) -> bytes:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def totp_code(secret: str, *, timestamp: int | None = None) -> str:
    counter = (timestamp if timestamp is not None else int(time.time())) // 30
    digest = hmac.new(
        _secret_bytes(secret),
        struct.pack(">Q", counter),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str, *, timestamp: int | None = None) -> bool:
    if len(code) != 6 or not code.isdigit():
        return False
    current = timestamp if timestamp is not None else int(time.time())
    return any(
        hmac.compare_digest(totp_code(secret, timestamp=current + offset), code)
        for offset in (-30, 0, 30)
    )


def _fernet() -> Fernet:
    key = hashlib.sha256(settings.secret_key.get_secret_value().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_totp_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_totp_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("MFA secret cannot be decrypted.") from exc


def provisioning_uri(username: str, secret: str) -> str:
    issuer = settings.mfa_issuer
    label = quote(f"{issuer}:{username}")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )
