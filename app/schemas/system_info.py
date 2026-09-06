from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import DateTime
from datetime import datetime

from app.database.base import Base


class SystemInfo(Base):

    __tablename__ = "system_info"

    id = Column(Integer, primary_key=True)

    service = Column(String(50), nullable=False)

    status = Column(String(20), nullable=False)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )
