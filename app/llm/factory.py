from app.core.exceptions import ServiceUnavailableException
from app.core.settings import settings
from app.llm.contracts import LLMProvider
from app.llm.ollama import OllamaProvider


def build_llm_provider() -> LLMProvider:
    if settings.llm_provider == "ollama":
        return OllamaProvider()
    raise ServiceUnavailableException(
        f"Unsupported LLM provider: {settings.llm_provider}."
    )
