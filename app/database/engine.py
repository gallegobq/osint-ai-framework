from sqlalchemy import create_engine

from app.core.config import config

engine = create_engine(
    config.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
)
