from typing import Generic
from typing import Type
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.base import Base

ModelType = TypeVar(
    "ModelType",
    bound=Base,
)


class BaseRepository(Generic[ModelType]):
    """
    Repositorio base reutilizable
    para cualquier modelo ORM.
    """

    def __init__(
        self,
        model: Type[ModelType],
        db: Session,
    ):
        self.model = model
        self.db = db

    def get_by_id(
        self,
        id: int,
    ) -> ModelType | None:

        return self.db.get(
            self.model,
            id,
        )

    def get_all(
        self,
    ) -> list[ModelType]:

        stmt = select(self.model)

        return list(
            self.db.scalars(stmt).all()
        )

    def create(
        self,
        obj: ModelType,
    ) -> ModelType:

        self.db.add(obj)

        self.db.flush()

        self.db.refresh(obj)

        return obj

    def update(self) -> None:

        self.db.flush()

    def delete(
        self,
        obj: ModelType,
    ) -> None:

        self.db.delete(obj)

        self.db.flush()

    def commit(self) -> None:

        self.db.commit()

    def rollback(self) -> None:

        self.db.rollback()
