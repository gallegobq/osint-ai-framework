from collections.abc import Generator

from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

# Register every mapped class before any standalone command (seed/worker/API)
# executes its first ORM query. Relationship targets use string references.
import app.models  # noqa: F401
from app.database.engine import engine


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """
    Crea una sesión de base de datos para cada petición.

    FastAPI abrirá la sesión antes de ejecutar el endpoint
    y la cerrará automáticamente al finalizar.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()
