from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from app.core.exceptions import ConflictException, NotFoundException
from app.models.evidence import Evidence, EvidenceSource, Entity, EntityRelation
from app.models.user import User
from app.repositories.entity_repository import (
    EntityRelationRepository,
    EntityRepository,
)
from app.repositories.evidence_repository import (
    EvidenceRepository,
    EvidenceSourceRepository,
)
from app.schemas.evidence import (
    EntityCreate,
    EntityRead,
    EntityRelationCreate,
    EntityRelationRead,
    EvidenceCreate,
    EvidenceRead,
)
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.investigation_service import InvestigationService


class EvidenceService:
    def __init__(
        self,
        repository: EvidenceRepository,
        source_repository: EvidenceSourceRepository,
        entity_repository: EntityRepository,
        relation_repository: EntityRelationRepository,
        investigations: InvestigationService,
        audit_service: AuditService,
    ):
        self.repository = repository
        self.sources = source_repository
        self.entities = entity_repository
        self.relations = relation_repository
        self.investigations = investigations
        self.audit = audit_service

    def add(
        self,
        actor: User,
        investigation_id: int,
        data: EvidenceCreate,
        *,
        commit: bool = True,
    ) -> EvidenceRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        now = datetime.now(timezone.utc)
        content_hash = self._content_hash(data)
        existing = self.repository.get_by_hash(
            investigation_id, content_hash
        )
        if existing is not None:
            return EvidenceRead.model_validate(existing)

        source = self.sources.get_by_identity(
            investigation_id,
            data.collector,
            data.locator,
        )
        if source is None:
            source = self.sources.create(
                EvidenceSource(
                    investigation_id=investigation_id,
                    collector=data.collector,
                    source_type=data.source_type,
                    locator=data.locator,
                    locator_hash=hashlib.sha256(
                        data.locator.encode("utf-8")
                    ).hexdigest(),
                    collected_at=now,
                    source_metadata=data.source_metadata,
                )
            )

        evidence = self.repository.create(
            Evidence(
                investigation_id=investigation_id,
                source_id=source.id,
                created_by_id=actor.id,
                kind=data.kind,
                title=data.title,
                content=data.content,
                content_hash=content_hash,
                observed_at=data.observed_at,
                collected_at=now,
                raw_data=data.raw_data,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="evidence.create",
            resource_type="evidence",
            resource_id=evidence.id,
            data={"investigation_id": investigation_id},
        )
        if commit:
            self.repository.commit()
        return EvidenceRead.model_validate(evidence)

    def list(
        self,
        actor: User,
        investigation_id: int,
        *,
        kind: str | None = None,
        search: str | None = None,
        limit: int = 200,
    ) -> list[EvidenceRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            EvidenceRead.model_validate(item)
            for item in self.repository.list_by_investigation(
                investigation_id,
                kind=kind,
                search=search,
                limit=limit,
            )
        ]

    def add_entity(
        self,
        actor: User,
        investigation_id: int,
        data: EntityCreate,
    ) -> EntityRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        existing = self.entities.get_by_identity(
            investigation_id,
            data.entity_type,
            data.canonical_name,
        )
        if existing is not None:
            return EntityRead.model_validate(existing)

        entity = self.entities.create(
            Entity(
                investigation_id=investigation_id,
                entity_type=data.entity_type,
                canonical_name=data.canonical_name,
                confidence=data.confidence,
                attributes=data.attributes,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="entities.create",
            resource_type="entity",
            resource_id=entity.id,
            data={"investigation_id": investigation_id},
        )
        self.repository.commit()
        return EntityRead.model_validate(entity)

    def list_entities(
        self,
        actor: User,
        investigation_id: int,
    ) -> list[EntityRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            EntityRead.model_validate(item)
            for item in self.entities.list_by_investigation(investigation_id)
        ]

    def add_relation(
        self,
        actor: User,
        investigation_id: int,
        data: EntityRelationCreate,
    ) -> EntityRelationRead:
        self.investigations.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        source = self.entities.get_by_id(data.source_entity_id)
        target = self.entities.get_by_id(data.target_entity_id)
        if (
            source is None
            or target is None
            or source.investigation_id != investigation_id
            or target.investigation_id != investigation_id
        ):
            raise NotFoundException("Investigation entity")
        if source.id == target.id:
            raise ConflictException("An entity cannot relate to itself.")

        if data.evidence_id is not None:
            evidence = self.repository.get_by_id(data.evidence_id)
            if (
                evidence is None
                or evidence.investigation_id != investigation_id
            ):
                raise NotFoundException("Investigation evidence")

        relation = self.relations.create(
            EntityRelation(
                investigation_id=investigation_id,
                source_entity_id=source.id,
                target_entity_id=target.id,
                evidence_id=data.evidence_id,
                relation_type=data.relation_type,
                confidence=data.confidence,
                attributes=data.attributes,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="relations.create",
            resource_type="entity_relation",
            resource_id=relation.id,
            data={"investigation_id": investigation_id},
        )
        self.repository.commit()
        return EntityRelationRead.model_validate(relation)

    def list_relations(
        self,
        actor: User,
        investigation_id: int,
    ) -> list[EntityRelationRead]:
        self.investigations.get_model(actor, investigation_id)
        return [
            EntityRelationRead.model_validate(item)
            for item in self.relations.list_by_investigation(investigation_id)
        ]

    @staticmethod
    def _content_hash(data: EvidenceCreate) -> str:
        canonical = json.dumps(
            {
                "collector": data.collector,
                "locator": data.locator,
                "kind": data.kind,
                "title": data.title,
                "content": data.content,
                "raw_data": data.raw_data,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
