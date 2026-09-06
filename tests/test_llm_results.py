import pytest
from pydantic import ValidationError

from app.llm.result_validation import validate_analysis_result
from app.schemas.job import AnalysisType


def test_summary_accepts_only_citations_from_context() -> None:
    result = validate_analysis_result(
        AnalysisType.SUMMARY,
        {
            "summary": "Observed registration data.",
            "key_findings": [
                {
                    "finding": "The domain has registration data.",
                    "evidence_ids": [7],
                    "confidence": 0.8,
                }
            ],
            "gaps": [],
        },
        {7},
    )

    assert result["key_findings"][0]["evidence_ids"] == [7]


def test_summary_rejects_citation_outside_context() -> None:
    with pytest.raises(ValueError, match="outside its context"):
        validate_analysis_result(
            AnalysisType.SUMMARY,
            {
                "summary": "Unsupported.",
                "key_findings": [
                    {
                        "finding": "Unsupported claim.",
                        "evidence_ids": [999],
                        "confidence": 1,
                    }
                ],
                "gaps": [],
            },
            {7},
        )


def test_llm_results_forbid_unexpected_fields() -> None:
    with pytest.raises(ValidationError):
        validate_analysis_result(
            AnalysisType.SENTIMENT,
            {
                "overall": "neutral",
                "confidence": 0.5,
                "items": [],
                "instructions": "ignored",
            },
            {7},
        )
