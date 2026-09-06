from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.dependencies.database import get_db
from app.core.container import build_audit_service
from app.services.audit_service import AuditService


def get_audit_service(
    db: Annotated[Session, Depends(get_db)],
) -> AuditService:
    return build_audit_service(db)
