from collections.abc import Generator

from sqlalchemy.orm import Session

from app.database.session import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    Crea una sesión por request.

    FastAPI la cierra automáticamente
    cuando termina la petición.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()
