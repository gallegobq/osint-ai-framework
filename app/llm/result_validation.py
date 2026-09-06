"""Contratos estrictos para resultados producidos por proveedores LLM."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.job import AnalysisType


class StrictResult(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Finding(StrictResult):
    finding: str = Field(min_length=1, max_length=5000)
    evidence_ids: list[int] = Field(min_length=1, max_length=100)
    confidence: float = Field(ge=0, le=1)


class SummaryResult(StrictResult):
    summary: str = Field(min_length=1, max_length=20_000)
    key_findings: list[Finding] = Field(max_length=200)
    gaps: list[str] = Field(max_length=200)


class EntityCandidate(StrictResult):
    type: Literal[
        "person",
        "company",
        "domain",
        "ip",
        "email",
        "location",
        "other",
    ]
    canonical_name: str = Field(min_length=1, max_length=255)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[int] = Field(min_length=1, max_length=100)
    attributes: dict = Field(default_factory=dict)


class EntitiesResult(StrictResult):
    entities: list[EntityCandidate] = Field(max_length=500)


class RelationCandidate(StrictResult):
    source: str = Field(min_length=1, max_length=255)
    target: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=100)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[int] = Field(min_length=1, max_length=100)


class RelationsResult(StrictResult):
    relations: list[RelationCandidate] = Field(max_length=500)


class SentimentItem(StrictResult):
    evidence_id: int = Field(gt=0)
    sentiment: Literal[
        "positive",
        "neutral",
        "negative",
        "mixed",
        "insufficient",
    ]
    confidence: float = Field(ge=0, le=1)


class SentimentResult(StrictResult):
    overall: Literal[
        "positive",
        "neutral",
        "negative",
        "mixed",
        "insufficient",
    ]
    confidence: float = Field(ge=0, le=1)
    items: list[SentimentItem] = Field(max_length=500)


RESULT_MODELS: dict[AnalysisType, type[StrictResult]] = {
    AnalysisType.SUMMARY: SummaryResult,
    AnalysisType.ENTITIES: EntitiesResult,
    AnalysisType.RELATIONS: RelationsResult,
    AnalysisType.SENTIMENT: SentimentResult,
}


def validate_analysis_result(
    analysis_type: AnalysisType,
    output: dict,
    allowed_evidence_ids: set[int],
) -> dict:
    """Valida estructura y evita citas fuera del contexto suministrado."""

    validated = RESULT_MODELS[analysis_type].model_validate(output)
    referenced_ids: set[int] = set()

    if isinstance(validated, SummaryResult):
        for finding in validated.key_findings:
            referenced_ids.update(finding.evidence_ids)
    elif isinstance(validated, EntitiesResult):
        for entity in validated.entities:
            referenced_ids.update(entity.evidence_ids)
    elif isinstance(validated, RelationsResult):
        for relation in validated.relations:
            referenced_ids.update(relation.evidence_ids)
    elif isinstance(validated, SentimentResult):
        referenced_ids.update(item.evidence_id for item in validated.items)

    invalid_ids = referenced_ids - allowed_evidence_ids
    if invalid_ids:
        raise ValueError("LLM output cited evidence outside its context.")

    return validated.model_dump(mode="json")
