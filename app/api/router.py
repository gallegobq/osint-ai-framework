from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.roles import router as roles_router
from app.api.v1.users import router as users_router
from app.api.v1.permissions import router as permissions_router
from app.api.v1.user_roles import router as user_roles_router
from app.api.v1.role_permissions import (
    router as role_permissions_router,
)
from app.api.v1.projects import router as projects_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.osint import router as osint_router
from app.api.v1.orchestration import router as orchestration_router
from app.api.v1.analyze import router as analysis_router
from app.api.v1.reports import router as reports_router
from app.api.v1.soc import router as soc_router
from app.api.v1.knowledge import router as knowledge_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(roles_router)
api_router.include_router(permissions_router)
api_router.include_router(user_roles_router)
api_router.include_router(role_permissions_router)
api_router.include_router(projects_router)
api_router.include_router(investigations_router)
api_router.include_router(evidence_router)
api_router.include_router(osint_router)
api_router.include_router(orchestration_router)
api_router.include_router(analysis_router)
api_router.include_router(reports_router)
api_router.include_router(soc_router)
api_router.include_router(knowledge_router)
