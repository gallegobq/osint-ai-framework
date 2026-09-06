from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.constants import ALEMBIC_HEAD


class HealthService:
    """Application readiness checks that do not expose infrastructure data."""

    def __init__(self, db: Session):
        self.db = db

    def database_is_ready(self) -> bool:
        try:
            self.db.execute(text("SELECT 1"))
            revision = self.db.scalar(
                text("SELECT version_num FROM alembic_version")
            )
        except SQLAlchemyError:
            return False

        return revision == ALEMBIC_HEAD
