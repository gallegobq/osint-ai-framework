import json

import httpx

from app.core.settings import settings
from app.llm.contracts import LLMProvider


class OllamaProvider(LLMProvider):
    name = "ollama"

    def generate_json(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> dict:
        with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
            response = client.post(
                f"{settings.ollama_url.rstrip('/')}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": schema or "json",
                    "options": {"temperature": 0},
                },
            )
            response.raise_for_status()
            payload = response.json()

        generated = payload.get("response")
        if not isinstance(generated, str):
            raise ValueError("Ollama response did not contain generated text.")

        result = json.loads(generated)
        if not isinstance(result, dict):
            raise ValueError("LLM output must be a JSON object.")
        return result

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
            response = client.post(
                f"{settings.ollama_url.rstrip('/')}/api/embed",
                json={
                    "model": settings.rag_embedding_model,
                    "input": texts,
                    "truncate": True,
                },
            )
            response.raise_for_status()
            payload = response.json()

        embeddings = payload.get("embeddings")
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise ValueError("Ollama returned an invalid embeddings response.")
        if any(
            not isinstance(vector, list)
            or not vector
            or any(not isinstance(value, (int, float)) for value in vector)
            for vector in embeddings
        ):
            raise ValueError("Ollama returned an invalid embedding vector.")
        dimensions = {len(vector) for vector in embeddings}
        if len(dimensions) != 1:
            raise ValueError("Ollama returned inconsistent embedding dimensions.")
        return [[float(value) for value in vector] for vector in embeddings]
