from abc import ABC, abstractmethod


class LLMProvider(ABC):
    name: str

    @abstractmethod
    def generate_json(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> dict:
        """Generate one JSON object from an evidence-grounded prompt."""

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate one embedding per input text."""
        raise NotImplementedError("This provider does not support embeddings.")
