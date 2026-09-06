from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """
    Hash de una contraseña usando Argon2.
    """
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verifica una contraseña.
    """
    return password_hash.verify(password, hashed_password)
