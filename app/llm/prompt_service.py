import json
from pathlib import Path

from app.core.settings import settings
from app.schemas.evidence import EvidenceRead
from app.schemas.job import AnalysisType


PROMPT_DIRECTORY = Path(__file__).resolve().parent / "prompts"


class PromptService:
    version = "v1"

    def build(
        self,
        analysis_type: AnalysisType,
        evidence: list[EvidenceRead],
    ) -> str:
        template = (PROMPT_DIRECTORY / f"{analysis_type.value}.txt").read_text(
            encoding="utf-8"
        )
        items = []
        remaining = settings.llm_max_evidence_characters

        for item in evidence:
            if remaining <= 0:
                break
            content = item.content[:remaining]
            remaining -= len(content)
            items.append(
                {
                    "evidence_id": item.id,
                    "kind": item.kind,
                    "title": item.title,
                    "content": content,
                    "observed_at": (
                        item.observed_at.isoformat()
                        if item.observed_at
                        else None
                    ),
                    "collected_at": item.collected_at.isoformat(),
                }
            )

        evidence_json = json.dumps(
            items,
            ensure_ascii=False,
            sort_keys=True,
        )
        return template.replace("{{EVIDENCE_JSON}}", evidence_json)
