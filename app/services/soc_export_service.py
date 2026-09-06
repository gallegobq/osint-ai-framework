import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone

from app.models.user import User
from app.repositories.entity_repository import EntityRepository
from app.repositories.evidence_repository import EvidenceRepository
from app.repositories.soc_repository import FindingRepository
from app.services.investigation_service import InvestigationService


STIX_NAMESPACE = uuid.UUID("8b7d6a00-f10b-4a65-9df1-585cf78d54a5")
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$", re.IGNORECASE)


def _stix_id(stix_type: str, identity: str) -> str:
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, identity)}"


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _hash_algorithm(value: str) -> str | None:
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(value))


class SocExportService:
    def __init__(
        self,
        investigations: InvestigationService,
        entities: EntityRepository,
        evidence: EvidenceRepository,
        findings: FindingRepository,
    ):
        self.investigations = investigations
        self.entities = entities
        self.evidence = evidence
        self.findings = findings

    def build_stix(self, actor: User, investigation_id: int) -> dict:
        investigation = self.investigations.get_model(actor, investigation_id)
        created = _timestamp(investigation.created_at)
        modified = _timestamp(investigation.updated_at)
        objects: list[dict] = []
        producer_id = f"identity--{uuid.uuid4()}"
        objects.append(
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": producer_id,
                "created": created,
                "modified": modified,
                "name": "OSINT AI Framework",
                "identity_class": "system",
            }
        )
        object_refs: list[str] = [producer_id]

        for entity in self.entities.list_by_investigation(investigation_id):
            item = self._entity_to_stix(entity)
            objects.append(item)
            object_refs.append(item["id"])

        evidence_by_id = {
            item.id: item
            for item in self.evidence.list_by_investigation(
                investigation_id, limit=1000
            )
        }
        for finding in self.findings.list_by_investigation(investigation_id):
            evidence = evidence_by_id.get(finding.evidence_id)
            note_id = f"note--{uuid.uuid4()}"
            note: dict = {
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created": _timestamp(finding.created_at),
                "modified": _timestamp(finding.updated_at),
                "created_by_ref": producer_id,
                "abstract": finding.title,
                "content": finding.description,
                "labels": ["soc-finding", finding.severity, finding.status],
                "object_refs": object_refs[:],
                "x_soc_severity": finding.severity,
                "x_soc_status": finding.status,
                "x_soc_confidence": float(finding.confidence),
            }
            if finding.remediation:
                note["x_soc_remediation"] = finding.remediation
            if evidence is not None:
                note["external_references"] = [
                    {
                        "source_name": evidence.source.source_metadata.get(
                            "provider", evidence.source.collector
                        ),
                        "url": evidence.source.locator
                        if evidence.source.locator.startswith(("http://", "https://"))
                        else None,
                        "external_id": evidence.content_hash,
                    }
                ]
                note["external_references"][0] = {
                    key: value
                    for key, value in note["external_references"][0].items()
                    if value is not None
                }
            objects.append(note)
            object_refs.append(note_id)

        grouping = {
            "type": "grouping",
            "spec_version": "2.1",
            "id": f"grouping--{uuid.uuid4()}",
            "created": created,
            "modified": modified,
            "name": investigation.title,
            "description": investigation.description or investigation.title,
            "context": "suspicious-activity",
            "object_refs": object_refs,
            "x_soc_operation_mode": investigation.operation_mode,
        }
        objects.append(grouping)
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def build_ndjson(self, actor: User, investigation_id: int) -> str:
        investigation = self.investigations.get_model(actor, investigation_id)
        events: list[dict] = []
        for finding in self.findings.list_by_investigation(investigation_id):
            events.append(
                {
                    "@timestamp": _timestamp(finding.updated_at),
                    "event": {
                        "kind": "alert",
                        "category": ["threat"],
                        "type": ["indicator"],
                        "action": "soc-finding",
                    },
                    "labels": {
                        "investigation_id": str(investigation.id),
                        "operation_mode": investigation.operation_mode,
                        "finding_status": finding.status,
                    },
                    "message": finding.description,
                    "rule": {"name": finding.title},
                    "threat": {"indicator": {"confidence": float(finding.confidence)}},
                    "vulnerability": {"severity": finding.severity},
                }
            )
        return "\n".join(
            json.dumps(event, ensure_ascii=False, separators=(",", ":"))
            for event in events
        )

    def build_cef(self, actor: User, investigation_id: int) -> str:
        investigation = self.investigations.get_model(actor, investigation_id)
        lines: list[str] = []
        severity = {
            "informational": 1,
            "low": 3,
            "medium": 5,
            "high": 8,
            "critical": 10,
        }
        for finding in self.findings.list_by_investigation(investigation_id):
            title = self._cef_escape(finding.title)
            description = self._cef_escape(finding.description)
            lines.append(
                "CEF:0|OSINT AI Framework|SOC Findings|1.0|"
                f"{finding.id}|{title}|{severity[finding.severity]}|"
                f"cs1={investigation.id} cs1Label=InvestigationId "
                f"cs2={finding.status} cs2Label=FindingStatus msg={description}"
            )
        return "\n".join(lines)

    @staticmethod
    def _cef_escape(value: str) -> str:
        return (
            " ".join(value.split())
            .replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("=", "\\=")
        )

    @staticmethod
    def _entity_to_stix(entity) -> dict:
        value = entity.canonical_name
        entity_type = entity.entity_type.lower()
        identity = f"entity:{entity.id}:{entity_type}:{value}"
        common = {"spec_version": "2.1"}
        if entity_type in {"domain", "hostname", "domain-name"}:
            stix_type = "domain-name"
            return {"type": stix_type, "id": _stix_id(stix_type, identity), "value": value, **common}
        if entity_type in {"ip", "ipv4", "ipv6"}:
            try:
                version = ipaddress.ip_address(value).version
            except ValueError:
                version = 4
            stix_type = f"ipv{version}-addr"
            return {"type": stix_type, "id": _stix_id(stix_type, identity), "value": value, **common}
        if entity_type in {"url", "uri"}:
            return {"type": "url", "id": _stix_id("url", identity), "value": value, **common}
        if entity_type in {"email", "email-addr"}:
            return {"type": "email-addr", "id": _stix_id("email-addr", identity), "value": value, **common}
        if entity_type in {"hash", "file_hash"} and _hash_algorithm(value):
            return {
                "type": "file",
                "id": _stix_id("file", identity),
                "hashes": {_hash_algorithm(value): value.lower()},
                **common,
            }
        if entity_type in {"cve", "vulnerability"} or CVE_PATTERN.fullmatch(value):
            return {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid4()}",
                "created": _timestamp(entity.created_at),
                "modified": _timestamp(entity.updated_at),
                "name": value.upper(),
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": value.upper(),
                        "url": f"https://nvd.nist.gov/vuln/detail/{value.upper()}",
                    }
                ],
            }
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "created": _timestamp(entity.created_at),
            "modified": _timestamp(entity.updated_at),
            "name": value,
            "identity_class": "organization" if entity_type == "company" else "individual",
            "labels": [entity_type],
        }
