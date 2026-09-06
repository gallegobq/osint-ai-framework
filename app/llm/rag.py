from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

WORD_PATTERN = re.compile(r"[\w.-]+", re.UNICODE)


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: int
    document_id: int
    document_title: str
    source_type: str
    source_uri: str | None
    content: str
    score: float


class RagCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunk_id: int = Field(gt=0)
    claim: str = Field(min_length=1, max_length=3000)


class RagAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str = Field(min_length=1, max_length=20_000)
    citations: list[RagCitation] = Field(max_length=50)
    confidence: float = Field(ge=0, le=1)
    gaps: list[str] = Field(max_length=50)


def chunk_text(content: str, size: int, overlap: int) -> list[str]:
    """Fragmenta por párrafos conservando solapamiento y límites estables."""

    normalized = re.sub(r"\r\n?", "\n", content).strip()
    if not normalized:
        return []

    chunks: list[str] = []
    start = 0
    length = len(normalized)
    while start < length:
        hard_end = min(start + size, length)
        end = hard_end
        if hard_end < length:
            candidates = [
                normalized.rfind("\n\n", start, hard_end),
                normalized.rfind(". ", start, hard_end),
                normalized.rfind("\n", start, hard_end),
                normalized.rfind(" ", start, hard_end),
            ]
            boundary = max(candidates)
            if boundary > start + size // 2:
                end = boundary + (2 if normalized[boundary : boundary + 2] == ". " else 0)

        chunk = normalized[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= length:
            break
        next_start = max(start + 1, end - overlap)
        while next_start < end and not normalized[next_start].isspace():
            next_start += 1
        start = next_start
    return chunks


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return numerator / (left_norm * right_norm)


def lexical_similarity(question: str, content: str) -> float:
    question_terms = {term.casefold() for term in WORD_PATTERN.findall(question)}
    content_terms = {term.casefold() for term in WORD_PATTERN.findall(content)}
    if not question_terms or not content_terms:
        return 0.0
    return len(question_terms & content_terms) / len(question_terms)


def hybrid_score(
    question: str,
    content: str,
    question_embedding: list[float],
    chunk_embedding: list[float],
) -> float:
    semantic = max(0.0, cosine_similarity(question_embedding, chunk_embedding))
    lexical = lexical_similarity(question, content)
    return round((semantic * 0.75) + (lexical * 0.25), 6)


def build_rag_prompt(question: str, chunks: list[RetrievedChunk]) -> str:
    template = (
        Path(__file__).resolve().parent / "prompts" / "soc_rag.txt"
    ).read_text(encoding="utf-8")
    context = [
        {
            "chunk_id": item.chunk_id,
            "document_id": item.document_id,
            "document_title": item.document_title,
            "source_type": item.source_type,
            "source_uri": item.source_uri,
            "content": item.content,
            "retrieval_score": item.score,
        }
        for item in chunks
    ]
    return template.replace("{{QUESTION}}", question).replace(
        "{{CONTEXT_JSON}}",
        json.dumps(context, ensure_ascii=False, sort_keys=True),
    )


def validate_rag_answer(output: dict, allowed_chunk_ids: set[int]) -> dict:
    validated = RagAnswer.model_validate(output)
    cited_ids = {citation.chunk_id for citation in validated.citations}
    if cited_ids - allowed_chunk_ids:
        raise ValueError("RAG output cited a chunk outside its context.")
    if validated.confidence > 0 and not validated.citations:
        raise ValueError("A confident RAG answer must include citations.")
    return validated.model_dump(mode="json")
