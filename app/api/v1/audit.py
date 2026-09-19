from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.authorization import require_permission
from app.core.container import build_audit_service
from app.core.permissions import Permissions
from app.dependencies.database import get_db
from app.models.user import User


router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/verify")
def verify_audit_chain(
    _current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Governance.MANAGE_RETENTION)),
    ],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, int | bool | str | None]:
    """Verify the append-only audit hash chain without exposing event data."""

    return build_audit_service(db).verify_chain()
