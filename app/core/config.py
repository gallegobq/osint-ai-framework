from sqlalchemy import URL

from app.core.settings import settings


class Config:
    """Valores derivados de Settings para adaptadores de infraestructura."""

    DATABASE_URL = URL.create(
        drivername="postgresql+psycopg2",
        username=settings.postgres_user,
        password=settings.postgres_password.get_secret_value(),
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
    )


config = Config()
