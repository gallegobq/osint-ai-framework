from collections import defaultdict
from datetime import datetime, timezone

from app.models.user import User
from app.repositories.job_repository import AnalysisJobRepository
from app.schemas.evidence import EvidenceRead
from app.schemas.job import AnalysisJobRead, AnalysisType, JobStatus
from app.schemas.report import InvestigationReport
from app.services.evidence_service import EvidenceService
from app.services.investigation_service import InvestigationService


EXPOSURE_GROUPS = (
    (
        "Domain and web infrastructure",
        (
            "dns",
            "domain",
            "certificate",
            "certspotter",
            "historical",
            "url_",
            "commoncrawl",
            "securitytrails",
            "virustotal_domain",
        ),
        (
            "Public DNS, registration, certificate, or historical web records "
            "make parts of the external web footprint visible."
        ),
    ),
    (
        "Network and routing information",
        (
            "ip_",
            "reverse_dns",
            "shodan",
            "virustotal_ip",
            "asn_",
        ),
        (
            "Public registration, routing, hostname, or service-index records "
            "describe parts of the network footprint."
        ),
    ),
    (
        "Public profiles and developer activity",
        (
            "github_user",
            "github_public_repositories",
            "gitlab_user",
            "bluesky_profile",
            "hackernews_user",
            "npm_maintained_packages",
        ),
        (
            "Public profile or developer-platform information was associated "
            "with the searched username. A matching alias alone does not prove "
            "identity."
        ),
    ),
    (
        "Public mentions and indexed content",
        (
            "wikidata",
            "wikipedia",
            "scholarly",
            "gdelt",
            "crossref",
            "openlibrary",
            "stackoverflow",
            "europepmc",
            "google_books",
            "hackernews_items",
        ),
        (
            "The search term appeared in public indexes, articles, books, "
            "research, or community content. These matches may include namesakes."
        ),
    ),
)

OTHER_EXPOSURE_GROUP = "Other documented observations"
OTHER_EXPOSURE_EXPLANATION = (
    "Additional observations were recorded but do not fit a predefined exposure "
    "category."
)


class ReportService:
    def __init__(
        self,
        investigations: InvestigationService,
        evidence: EvidenceService,
        analysis_repository: AnalysisJobRepository,
    ):
        self.investigations = investigations
        self.evidence = evidence
        self.analysis_repository = analysis_repository

    def build(self, actor: User, investigation_id: int) -> InvestigationReport:
        investigation = self.investigations.get(actor, investigation_id)
        evidence = self.evidence.list(actor, investigation_id)
        entities = self.evidence.list_entities(actor, investigation_id)
        relations = self.evidence.list_relations(actor, investigation_id)
        analyses = [
            AnalysisJobRead.model_validate(job)
            for job in self.analysis_repository.list_by_investigation(
                investigation_id
            )
            if job.status == JobStatus.SUCCEEDED.value
        ]
        warnings = [
            "AI-assisted observations are hypotheses that require human review.",
            "Absence of evidence is not evidence of absence.",
        ]
        if not evidence:
            warnings.append("This report contains no evidence records.")

        return InvestigationReport(
            generated_at=datetime.now(timezone.utc),
            investigation=investigation,
            evidence=evidence,
            entities=entities,
            relations=relations,
            analyses=analyses,
            warnings=warnings,
        )

    def render_markdown(self, report: InvestigationReport) -> str:
        investigation = report.investigation
        groups = self._group_evidence(report.evidence)
        source_count = len({item.source_id for item in report.evidence})
        evidence_count = len(report.evidence)

        lines = [
            f"# Public exposure report: {investigation.title}",
            "",
            "## Executive summary",
            "",
        ]
        if report.evidence:
            surfaces = self._natural_list(list(groups))
            lines.extend(
                [
                    (
                        f"The search returned **{evidence_count} evidence "
                        f"record{self._plural(evidence_count)}** from "
                        f"**{source_count} distinct public "
                        f"source{self._plural(source_count)}**. Publicly visible "
                        f"data was observed across these exposure surfaces: "
                        f"**{surfaces}**."
                    ),
                    "",
                    (
                        "This means that third parties may be able to find some of "
                        "the same information through public services. It does "
                        "**not** by itself prove a security vulnerability, data "
                        "breach, account compromise, or common ownership."
                    ),
                ]
            )
        else:
            lines.extend(
                [
                    (
                        "The search did not return evidence records from the "
                        "configured public sources. This does not prove that no "
                        "public information exists."
                    ),
                    "",
                    (
                        "Coverage can be affected by provider availability, query "
                        "scope, indexing delays, rate limits, and unsupported "
                        "platforms."
                    ),
                ]
            )

        lines.extend(
            [
                "",
                "## Report at a glance",
                "",
                f"- Evidence records: **{evidence_count}**",
                f"- Distinct public sources: **{source_count}**",
                f"- Structured entities: **{len(report.entities)}**",
                f"- Recorded relationships: **{len(report.relations)}**",
                f"- Operation mode: **{self._words(investigation.operation_mode.value)}**",
                f"- Investigation status: **{self._words(investigation.status.value)}**",
                f"- Generated: {report.generated_at.isoformat()}",
                "",
                "## What the search found",
                "",
            ]
        )

        if groups:
            evidence_by_id = {item.id: item for item in report.evidence}
            for group_name, evidence_ids in groups.items():
                lines.extend(
                    [
                        f"### {group_name}",
                        "",
                        self._group_explanation(group_name),
                        "",
                    ]
                )
                for evidence_id in evidence_ids:
                    item = evidence_by_id[evidence_id]
                    lines.append(f"- {self._inline(item.title)} [E{item.id}]")
                lines.append("")
        else:
            lines.extend(
                [
                    "No evidence-backed exposure surface can be described yet.",
                    "",
                ]
            )

        lines.extend(["## Plain-language assessment", ""])
        lines.extend(self._assessment(groups, report.evidence))
        lines.extend(["", "## Recommended next steps", ""])
        lines.extend(self._recommendations(groups))
        lines.extend(["", "## AI-assisted observations", ""])
        lines.extend(self._render_analyses(report.analyses))

        lines.extend(
            [
                "",
                "## Scope and methodology",
                "",
                investigation.description or "No investigation description was provided.",
                "",
                (
                    "Authorization scope: "
                    + (
                        investigation.authorization_scope
                        or "Passive public-source collection only."
                    )
                ),
                "",
                (
                    "Active testing was authorized for this investigation."
                    if investigation.active_testing_authorized
                    else "No active testing was authorized for this investigation."
                ),
                "",
                "## Structured records",
                "",
            ]
        )

        if report.entities:
            lines.append("### Entities")
            lines.append("")
            for entity in report.entities:
                lines.append(
                    f"- {self._inline(entity.canonical_name)} "
                    f"({self._words(entity.entity_type)}, confidence "
                    f"{self._confidence(entity.confidence)})"
                )
            lines.append("")
        else:
            lines.extend(["No structured entities have been recorded.", ""])

        if report.relations:
            lines.append("### Relationships")
            lines.append("")
            for relation in report.relations:
                citation = (
                    f" [E{relation.evidence_id}]" if relation.evidence_id else ""
                )
                lines.append(
                    f"- Entity {relation.source_entity_id} "
                    f"—{self._words(relation.relation_type)}→ "
                    f"Entity {relation.target_entity_id}{citation}"
                )
            lines.append("")
        else:
            lines.extend(["No structured relationships have been recorded.", ""])

        lines.extend(["## Technical evidence appendix", ""])
        if report.evidence:
            for item in report.evidence:
                lines.extend(
                    [
                        f"### [E{item.id}] {self._inline(item.title)}",
                        "",
                        f"- Type: `{item.kind}`",
                        f"- Source record: `{item.source_id}`",
                        f"- SHA-256: `{item.content_hash}`",
                        f"- Collected: {item.collected_at.isoformat()}",
                        "",
                        "<details>",
                        "<summary>Show collected content</summary>",
                        "",
                        "```text",
                        self._safe_code_block(item.content),
                        "```",
                        "",
                        "</details>",
                        "",
                    ]
                )
        else:
            lines.extend(["No evidence records are available.", ""])

        lines.extend(["## Important limitations", ""])
        lines.extend(f"- {warning}" for warning in report.warnings)
        lines.extend(
            [
                (
                    "- Public visibility can create exposure, but exposure is not "
                    "the same as confirmed risk. Validate every material finding "
                    "against the original source."
                ),
                "",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _group_evidence(evidence: list[EvidenceRead]) -> dict[str, list[int]]:
        groups: dict[str, list[int]] = defaultdict(list)
        for item in evidence:
            group_name = OTHER_EXPOSURE_GROUP
            kind = item.kind.lower()
            for candidate, markers, _ in EXPOSURE_GROUPS:
                if any(marker in kind for marker in markers):
                    group_name = candidate
                    break
            groups[group_name].append(item.id)
        return dict(groups)

    @staticmethod
    def _group_explanation(group_name: str) -> str:
        for candidate, _, explanation in EXPOSURE_GROUPS:
            if candidate == group_name:
                return explanation
        return OTHER_EXPOSURE_EXPLANATION

    @classmethod
    def _assessment(
        cls,
        groups: dict[str, list[int]],
        evidence: list[EvidenceRead],
    ) -> list[str]:
        if not evidence:
            return [
                (
                    "- No conclusion about exposure can be made from this run. "
                    "Review the scope and unavailable sources before repeating it."
                )
            ]

        lines = [
            (
                "- The investigation confirmed public visibility in "
                f"{len(groups)} exposure surface{cls._plural(len(groups))}."
            )
        ]
        if "Domain and web infrastructure" in groups:
            lines.append(
                "- External infrastructure metadata can help others map the web footprint."
            )
        if "Network and routing information" in groups:
            lines.append(
                "- Network ownership or routing context is discoverable in public indexes."
            )
        if "Public profiles and developer activity" in groups:
            lines.append(
                "- Public profile information may contribute to identity correlation, "
                "but each match needs manual verification."
            )
        if "Public mentions and indexed content" in groups:
            lines.append(
                "- Indexed mentions increase discoverability but may refer to unrelated "
                "people or organizations with similar names."
            )
        lines.append(
            "- No collected record alone confirms exploitation, compromise, or harmful intent."
        )
        return lines

    @staticmethod
    def _recommendations(groups: dict[str, list[int]]) -> list[str]:
        lines = [
            "- Open each cited source and confirm that the observation is still current.",
            "- Remove false positives before sharing or acting on this report.",
        ]
        if "Domain and web infrastructure" in groups:
            lines.append(
                "- Review stale DNS, certificates, historical hosts, and unnecessary "
                "public metadata against the authorized asset inventory."
            )
        if "Network and routing information" in groups:
            lines.append(
                "- Confirm that publicly indexed network services and ownership data "
                "match the expected environment."
            )
        if "Public profiles and developer activity" in groups:
            lines.append(
                "- Review profile privacy settings and remove secrets or unnecessary "
                "personal information from public repositories and profiles."
            )
        if "Public mentions and indexed content" in groups:
            lines.append(
                "- Verify namesakes and context before attributing any public mention "
                "to the target."
            )
        lines.append(
            "- Record remediation decisions and retain only the evidence required by policy."
        )
        return lines

    @classmethod
    def _render_analyses(cls, analyses: list[AnalysisJobRead]) -> list[str]:
        if not analyses:
            return [
                (
                    "No completed AI analysis is included. The plain-language sections "
                    "above were generated deterministically and used no LLM tokens."
                )
            ]

        lines = [
            (
                "The following observations were generated by AI from collected evidence. "
                "They require human review."
            ),
            "",
        ]
        for analysis in analyses:
            result = analysis.result or {}
            lines.extend([f"### {cls._words(analysis.analysis_type.value)}", ""])
            if analysis.analysis_type == AnalysisType.SUMMARY:
                lines.append(str(result.get("summary", "No summary was returned.")))
                lines.append("")
                for finding in result.get("key_findings", []):
                    citations = cls._citations(finding.get("evidence_ids", []))
                    confidence = cls._confidence(finding.get("confidence", 0))
                    lines.append(
                        f"- {finding.get('finding', 'Unspecified finding')} "
                        f"{citations} (confidence {confidence})"
                    )
                gaps = result.get("gaps", [])
                if gaps:
                    lines.extend(["", "Known information gaps:"])
                    lines.extend(f"- {gap}" for gap in gaps)
            elif analysis.analysis_type == AnalysisType.ENTITIES:
                for entity in result.get("entities", []):
                    lines.append(
                        f"- {entity.get('canonical_name', 'Unnamed entity')} "
                        f"({cls._words(entity.get('type', 'other'))}, confidence "
                        f"{cls._confidence(entity.get('confidence', 0))}) "
                        f"{cls._citations(entity.get('evidence_ids', []))}"
                    )
            elif analysis.analysis_type == AnalysisType.RELATIONS:
                for relation in result.get("relations", []):
                    lines.append(
                        f"- {relation.get('source', 'Unknown source')} "
                        f"—{cls._words(relation.get('type', 'related to'))}→ "
                        f"{relation.get('target', 'unknown target')} "
                        f"{cls._citations(relation.get('evidence_ids', []))}"
                    )
            elif analysis.analysis_type == AnalysisType.SENTIMENT:
                lines.append(
                    "The collected text was classified as "
                    f"**{cls._words(result.get('overall', 'insufficient'))}** "
                    f"with confidence {cls._confidence(result.get('confidence', 0))}. "
                    "This describes wording, not a factual judgment about a person."
                )
            lines.append("")
        return lines

    @staticmethod
    def _natural_list(values: list[str]) -> str:
        if not values:
            return "none"
        if len(values) == 1:
            return values[0]
        if len(values) == 2:
            return " and ".join(values)
        return f"{', '.join(values[:-1])}, and {values[-1]}"

    @staticmethod
    def _citations(evidence_ids: list[int]) -> str:
        return ", ".join(f"[E{evidence_id}]" for evidence_id in evidence_ids)

    @staticmethod
    def _confidence(value: object) -> str:
        try:
            return f"{float(value):.0%}"
        except (TypeError, ValueError):
            return "unknown"

    @staticmethod
    def _words(value: object) -> str:
        return str(value).replace("_", " ").strip().capitalize()

    @staticmethod
    def _inline(value: object) -> str:
        return " ".join(str(value).splitlines()).strip()

    @staticmethod
    def _safe_code_block(value: str) -> str:
        return value.replace("```", "` ` `")

    @staticmethod
    def _plural(count: int) -> str:
        return "" if count == 1 else "s"
