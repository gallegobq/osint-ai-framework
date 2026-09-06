from __future__ import annotations

import hashlib

from app.core.exceptions import BadRequestException, ConflictException
from app.core.exceptions import ServiceUnavailableException
from app.core.settings import settings
from app.llm.contracts import LLMProvider
from app.llm.rag import (
    RagAnswer,
    RetrievedChunk,
    build_rag_prompt,
    chunk_text,
    hybrid_score,
    validate_rag_answer,
)
from app.models.knowledge import KnowledgeChunk, KnowledgeDocument
from app.models.user import User
from app.repositories.knowledge_repository import (
    KnowledgeChunkRepository,
    KnowledgeDocumentRepository,
)
from app.schemas.knowledge import (
    KnowledgeDocumentCreate,
    KnowledgeDocumentRead,
    RagCitationRead,
    RagQuery,
    RagQueryResult,
)
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.project_service import ProjectService


class KnowledgeService:
    def __init__(
        self,
        documents: KnowledgeDocumentRepository,
        chunks: KnowledgeChunkRepository,
        projects: ProjectService,
        audit: AuditService,
        provider: LLMProvider,
    ):
        self.documents = documents
        self.chunks = chunks
        self.projects = projects
        self.audit = audit
        self.provider = provider

    def ingest(
        self,
        actor: User,
        project_id: int,
        data: KnowledgeDocumentCreate,
    ) -> KnowledgeDocumentRead:
        self.projects.get(
            actor, project_id, minimum_role=ProjectMemberRole.EDITOR
        )
        content = data.content.strip()
        if len(content) > settings.rag_max_document_characters:
            raise BadRequestException(
                "Knowledge document exceeds the configured size limit."
            )

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        existing = self.documents.get_by_hash(project_id, content_hash)
        if existing is not None:
            return KnowledgeDocumentRead.model_validate(existing)

        parts = chunk_text(
            content,
            settings.rag_chunk_characters,
            settings.rag_chunk_overlap_characters,
        )
        if not parts:
            raise BadRequestException("Knowledge document has no indexable text.")
        current_count = self.chunks.count_by_project(project_id)
        if current_count + len(parts) > settings.rag_max_chunks_per_project:
            raise ConflictException(
                "Project knowledge base reached its configured chunk limit."
            )

        try:
            embeddings = self._embed_batches(parts)
        except Exception as exc:
            raise ServiceUnavailableException(
                "The local embedding model is unavailable."
            ) from exc

        document = KnowledgeDocument(
            project_id=project_id,
            created_by_id=actor.id,
            title=data.title,
            source_type=data.source_type.value,
            source_uri=data.source_uri,
            content=content,
            content_hash=content_hash,
            status="indexed",
            embedding_model=settings.rag_embedding_model,
            chunk_count=len(parts),
            document_metadata=data.metadata,
        )
        try:
            self.documents.create(document)
            for position, (part, embedding) in enumerate(
                zip(parts, embeddings, strict=True)
            ):
                self.chunks.create(
                    KnowledgeChunk(
                        document_id=document.id,
                        project_id=project_id,
                        position=position,
                        content=part,
                        content_hash=hashlib.sha256(
                            part.encode("utf-8")
                        ).hexdigest(),
                        character_count=len(part),
                        embedding=embedding,
                    )
                )
            self.audit.record(
                actor_user_id=actor.id,
                action="knowledge.ingest",
                resource_type="knowledge_document",
                resource_id=document.id,
                data={"project_id": project_id, "chunks": len(parts)},
            )
            self.documents.commit()
        except Exception:
            self.documents.rollback()
            raise
        return KnowledgeDocumentRead.model_validate(document)

    def list(
        self, actor: User, project_id: int
    ) -> list[KnowledgeDocumentRead]:
        self.projects.get(actor, project_id)
        return [
            KnowledgeDocumentRead.model_validate(document)
            for document in self.documents.list_by_project(project_id)
        ]

    def query(
        self, actor: User, project_id: int, data: RagQuery
    ) -> RagQueryResult:
        self.projects.get(actor, project_id)
        candidates = self.chunks.list_by_project(
            project_id, limit=settings.rag_max_chunks_per_project
        )
        if not candidates:
            raise BadRequestException(
                "The project knowledge base is empty. Ingest a SOC document first."
            )
        try:
            question_embedding = self.provider.embed([data.question])[0]
        except Exception as exc:
            raise ServiceUnavailableException(
                "The local embedding model is unavailable."
            ) from exc

        ranked = sorted(
            (
                RetrievedChunk(
                    chunk_id=chunk.id,
                    document_id=chunk.document_id,
                    document_title=chunk.document.title,
                    source_type=chunk.document.source_type,
                    source_uri=chunk.document.source_uri,
                    content=chunk.content,
                    score=hybrid_score(
                        data.question,
                        chunk.content,
                        question_embedding,
                        [float(value) for value in chunk.embedding],
                    ),
                )
                for chunk in candidates
                if chunk.document.embedding_model == settings.rag_embedding_model
            ),
            key=lambda item: (-item.score, item.chunk_id),
        )
        context = [item for item in ranked if item.score >= data.minimum_score][
            : data.top_k
        ]
        if not context:
            return RagQueryResult(
                answer="No hay contexto suficiente en la base de conocimiento SOC.",
                citations=[],
                confidence=0,
                gaps=["Faltan documentos relevantes para responder la pregunta."],
                embedding_model=settings.rag_embedding_model,
            )

        try:
            output = self.provider.generate_json(
                build_rag_prompt(data.question, context),
                schema=RagAnswer.model_json_schema(),
            )
            validated = validate_rag_answer(
                output, {item.chunk_id for item in context}
            )
        except Exception as exc:
            raise ServiceUnavailableException(
                "The local RAG answer could not be generated safely."
            ) from exc

        context_by_id = {item.chunk_id: item for item in context}
        citations = [
            RagCitationRead(
                chunk_id=citation["chunk_id"],
                document_id=context_by_id[citation["chunk_id"]].document_id,
                document_title=context_by_id[citation["chunk_id"]].document_title,
                source_type=context_by_id[citation["chunk_id"]].source_type,
                source_uri=context_by_id[citation["chunk_id"]].source_uri,
                claim=citation["claim"],
                score=context_by_id[citation["chunk_id"]].score,
            )
            for citation in validated["citations"]
        ]
        self.audit.record(
            actor_user_id=actor.id,
            action="knowledge.query",
            resource_type="project",
            resource_id=project_id,
            data={
                "retrieved_chunk_ids": [item.chunk_id for item in context],
                "cited_chunk_ids": [item.chunk_id for item in citations],
            },
        )
        self.documents.commit()
        return RagQueryResult(
            answer=validated["answer"],
            citations=citations,
            confidence=validated["confidence"],
            gaps=validated["gaps"],
            embedding_model=settings.rag_embedding_model,
        )

    def _embed_batches(self, texts: list[str]) -> list[list[float]]:
        embeddings: list[list[float]] = []
        batch_size = settings.rag_embedding_batch_size
        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            result = self.provider.embed(batch)
            if len(result) != len(batch):
                raise ValueError("Embedding provider returned an invalid batch.")
            embeddings.extend(result)
        return embeddings
