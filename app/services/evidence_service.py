from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from app.core.exceptions import ConflictException, NotFoundException
from app.core.settings import settings
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
    EvidenceIntegrityVerification,
    EvidenceRead,
)
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.investigation_service import InvestigationService


class EvidenceService:
    INTEGRITY_VERSION = 2
    LEGACY_INTEGRITY_VERSION = 1
    LEGACY_KEY_ID = "legacy-secret-key"
    _SIGNING_CONTEXT = b"linterna/evidence-integrity/v2"

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

        content_hash = self._content_hash(data, source=source)
        existing = self.repository.get_by_hash(investigation_id, content_hash)
        if existing is None:
            legacy_hash = self._legacy_content_hash(data)
            legacy = self.repository.get_by_hash(investigation_id, legacy_hash)
            if (
                legacy is not None
                and legacy.integrity_version == self.LEGACY_INTEGRITY_VERSION
                and hmac.compare_digest(
                    self._content_hash_from_evidence(legacy),
                    content_hash,
                )
            ):
                existing = legacy
        if existing is not None:
            return EvidenceRead.model_validate(existing)

        signing_key = self._signing_key()
        key_id = self._key_id(signing_key)
        evidence = Evidence(
            investigation_id=investigation_id,
            source_id=source.id,
            created_by_id=actor.id,
            kind=data.kind,
            title=data.title,
            content=data.content,
            content_hash=content_hash,
            integrity_signature="",
            integrity_version=self.INTEGRITY_VERSION,
            integrity_key_id=key_id,
            observed_at=data.observed_at,
            collected_at=now,
            raw_data=data.raw_data,
            source=source,
        )
        evidence.integrity_signature = self._sign_manifest(
            self._integrity_manifest(evidence, content_hash=content_hash),
            signing_key,
        )
        evidence = self.repository.create(evidence)
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

    def verify_integrity(
        self,
        actor: User,
        investigation_id: int,
        evidence_id: int,
    ) -> EvidenceIntegrityVerification:
        self.investigations.get_model(actor, investigation_id)
        evidence = self.repository.get_by_id(evidence_id)
        if (
            evidence is None
            or evidence.investigation_id != investigation_id
        ):
            raise NotFoundException("Investigation evidence")

        return self._verify_integrity(evidence)

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

    @classmethod
    def _content_hash(
        cls,
        data: EvidenceCreate,
        *,
        source: EvidenceSource | None = None,
    ) -> str:
        payload = {
            "schema": "linterna-evidence-content/v2",
            "source": {
                "collector": source.collector if source else data.collector,
                "source_type": (
                    source.source_type if source else data.source_type
                ),
                "locator": source.locator if source else data.locator,
                "metadata": (
                    source.source_metadata
                    if source
                    else data.source_metadata
                ),
            },
            "observation": {
                "kind": data.kind,
                "title": data.title,
                "content": data.content,
                "observed_at": cls._canonical_datetime(data.observed_at),
                "raw_data": data.raw_data,
            },
        }
        return cls._sha256(payload)

    @classmethod
    def _content_hash_from_evidence(cls, evidence: Evidence) -> str:
        source = evidence.source
        payload = {
            "schema": "linterna-evidence-content/v2",
            "source": {
                "collector": source.collector,
                "source_type": source.source_type,
                "locator": source.locator,
                "metadata": source.source_metadata,
            },
            "observation": {
                "kind": evidence.kind,
                "title": evidence.title,
                "content": evidence.content,
                "observed_at": cls._canonical_datetime(
                    evidence.observed_at
                ),
                "raw_data": evidence.raw_data,
            },
        }
        return cls._sha256(payload)

    @classmethod
    def _legacy_content_hash(cls, data: EvidenceCreate) -> str:
        return cls._sha256(
            {
                "collector": data.collector,
                "locator": data.locator,
                "kind": data.kind,
                "title": data.title,
                "content": data.content,
                "raw_data": data.raw_data,
            }
        )

    @classmethod
    def _legacy_content_hash_from_evidence(
        cls,
        evidence: Evidence,
    ) -> str:
        return cls._sha256(
            {
                "collector": evidence.source.collector,
                "locator": evidence.source.locator,
                "kind": evidence.kind,
                "title": evidence.title,
                "content": evidence.content,
                "raw_data": evidence.raw_data,
            }
        )

    @classmethod
    def _integrity_manifest(
        cls,
        evidence: Evidence,
        *,
        content_hash: str,
    ) -> dict:
        source = evidence.source
        return {
            "schema": "linterna-evidence-integrity/v2",
            "integrity_version": cls.INTEGRITY_VERSION,
            "integrity_key_id": evidence.integrity_key_id,
            "investigation_id": evidence.investigation_id,
            "source_id": evidence.source_id,
            "created_by_id": evidence.created_by_id,
            "source": {
                "collector": source.collector,
                "source_type": source.source_type,
                "locator": source.locator,
                "locator_hash": source.locator_hash,
                "collected_at": cls._canonical_datetime(
                    source.collected_at
                ),
                "metadata": source.source_metadata,
            },
            "observation": {
                "kind": evidence.kind,
                "title": evidence.title,
                "content": evidence.content,
                "content_hash": content_hash,
                "observed_at": cls._canonical_datetime(
                    evidence.observed_at
                ),
                "collected_at": cls._canonical_datetime(
                    evidence.collected_at
                ),
                "raw_data": evidence.raw_data,
            },
        }

    def _verify_integrity(
        self,
        evidence: Evidence,
    ) -> EvidenceIntegrityVerification:
        warnings: list[str] = []
        version = evidence.integrity_version
        signature = evidence.integrity_signature or ""

        if version == self.LEGACY_INTEGRITY_VERSION:
            scheme = "legacy-v1"
            expected_hash = self._legacy_content_hash_from_evidence(evidence)
            content_hash_valid = hmac.compare_digest(
                evidence.content_hash,
                expected_hash,
            )
            expected_signature = hmac.new(
                settings.secret_key.get_secret_value().encode("utf-8"),
                expected_hash.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            signature_valid = hmac.compare_digest(
                signature,
                expected_signature,
            )
            key_available = True
            warnings.append(
                "Legacy v1 does not authenticate source metadata, timestamps, "
                "creator, or investigation association."
            )
        elif version == self.INTEGRITY_VERSION:
            scheme = "canonical-v2"
            expected_hash = self._content_hash_from_evidence(evidence)
            content_hash_valid = hmac.compare_digest(
                evidence.content_hash,
                expected_hash,
            )
            signing_key = self._signing_key()
            current_key_id = self._key_id(signing_key)
            key_available = hmac.compare_digest(
                evidence.integrity_key_id,
                current_key_id,
            )
            if key_available:
                expected_signature = self._sign_manifest(
                    self._integrity_manifest(
                        evidence,
                        content_hash=expected_hash,
                    ),
                    signing_key,
                )
                signature_valid = hmac.compare_digest(
                    signature,
                    expected_signature,
                )
            else:
                signature_valid = False
                warnings.append(
                    "The signing key recorded for this evidence is not "
                    "available in the current configuration."
                )
        else:
            scheme = "unknown"
            content_hash_valid = False
            signature_valid = False
            key_available = False
            warnings.append("Unsupported evidence integrity version.")

        if not content_hash_valid:
            warnings.append("The canonical evidence hash does not match.")
        if not signature_valid:
            warnings.append("The evidence signature does not match.")

        return EvidenceIntegrityVerification(
            evidence_id=evidence.id,
            valid=content_hash_valid and signature_valid,
            content_hash_valid=content_hash_valid,
            signature_valid=signature_valid,
            integrity_version=version,
            scheme=scheme,
            key_id=evidence.integrity_key_id,
            key_available=key_available,
            verified_at=datetime.now(timezone.utc),
            warnings=warnings,
        )

    @classmethod
    def _sha256(cls, payload: dict) -> str:
        return hashlib.sha256(
            cls._canonical_json(payload).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _canonical_json(payload: dict) -> str:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

    @staticmethod
    def _canonical_datetime(value: datetime | None) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(timezone.utc)
        return value.isoformat(timespec="microseconds").replace(
            "+00:00",
            "Z",
        )

    @classmethod
    def _signing_key(cls) -> bytes:
        configured = settings.evidence_signing_key
        if configured is not None:
            return configured.get_secret_value().encode("utf-8")
        root_key = settings.secret_key.get_secret_value().encode("utf-8")
        return hmac.new(
            root_key,
            cls._SIGNING_CONTEXT,
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _key_id(signing_key: bytes) -> str:
        fingerprint = hashlib.sha256(signing_key).hexdigest()[:16]
        return f"sha256:{fingerprint}"

    @classmethod
    def _sign_manifest(cls, manifest: dict, signing_key: bytes) -> str:
        return hmac.new(
            signing_key,
            cls._canonical_json(manifest).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
