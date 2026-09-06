from sqlalchemy.orm import Session

from app.repositories.audit_repository import AuditRepository
from app.repositories.entity_repository import (
    EntityRelationRepository,
    EntityRepository,
)
from app.repositories.evidence_repository import (
    EvidenceRepository,
    EvidenceSourceRepository,
)
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.project_repository import (
    ProjectMemberRepository,
    ProjectRepository,
)
from app.repositories.task_repository import TaskRepository
from app.repositories.user_repository import UserRepository
from app.repositories.soc_repository import FindingRepository, SearchScheduleRepository
from app.services.audit_service import AuditService
from app.services.evidence_service import EvidenceService
from app.services.investigation_service import InvestigationService
from app.services.project_service import ProjectService
from app.services.soc_service import SocService


def build_audit_service(db: Session) -> AuditService:
    return AuditService(AuditRepository(db))


def build_project_service(db: Session) -> ProjectService:
    return ProjectService(
        project_repository=ProjectRepository(db),
        member_repository=ProjectMemberRepository(db),
        user_repository=UserRepository(db),
        audit_service=build_audit_service(db),
    )


def build_investigation_service(db: Session) -> InvestigationService:
    return InvestigationService(
        repository=InvestigationRepository(db),
        task_repository=TaskRepository(db),
        user_repository=UserRepository(db),
        project_service=build_project_service(db),
        audit_service=build_audit_service(db),
    )


def build_evidence_service(db: Session) -> EvidenceService:
    return EvidenceService(
        repository=EvidenceRepository(db),
        source_repository=EvidenceSourceRepository(db),
        entity_repository=EntityRepository(db),
        relation_repository=EntityRelationRepository(db),
        investigations=build_investigation_service(db),
        audit_service=build_audit_service(db),
    )


def build_soc_service(db: Session) -> SocService:
    return SocService(
        findings=FindingRepository(db),
        schedules=SearchScheduleRepository(db),
        evidence=EvidenceRepository(db),
        investigations=build_investigation_service(db),
        audit=build_audit_service(db),
    )
