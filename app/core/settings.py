"""
Application settings.

Este módulo carga toda la configuración desde el archivo .env
utilizando Pydantic Settings.

Ningún otro módulo del proyecto debe utilizar os.getenv().
Toda la configuración debe obtenerse desde la instancia global
`settings`.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configuración global de la aplicación.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ==========================================================
    # APPLICATION
    # ==========================================================

    app_name: str = Field(alias="APP_NAME")
    app_version: str = Field(alias="APP_VERSION")

    debug: bool = Field(alias="DEBUG")

    host: str = Field(alias="HOST")
    port: int = Field(alias="PORT")

    # ==========================================================
    # DATABASE
    # ==========================================================

    postgres_host: str = Field(alias="POSTGRES_HOST")
    postgres_port: int = Field(alias="POSTGRES_PORT")

    postgres_db: str = Field(alias="POSTGRES_DB")

    postgres_user: str = Field(alias="POSTGRES_USER")

    postgres_password: SecretStr = Field(alias="POSTGRES_PASSWORD")

    # ==========================================================
    # SECURITY
    # ==========================================================

    secret_key: SecretStr = Field(
        alias="SECRET_KEY",
        min_length=32,
    )

    jwt_algorithm: Literal["HS256"] = Field(alias="JWT_ALGORITHM")

    access_token_expire_minutes: int = Field(
        alias="ACCESS_TOKEN_EXPIRE_MINUTES"
    )

    refresh_token_expire_days: int = Field(
        alias="REFRESH_TOKEN_EXPIRE_DAYS"
    )
    mfa_issuer: str = Field(
        default="OSINT AI Framework",
        alias="MFA_ISSUER",
        min_length=3,
        max_length=100,
    )

    initial_admin_username: str | None = Field(
        default=None,
        alias="INITIAL_ADMIN_USERNAME",
    )

    initial_admin_email: str | None = Field(
        default=None,
        alias="INITIAL_ADMIN_EMAIL",
    )

    initial_admin_password: SecretStr | None = Field(
        default=None,
        alias="INITIAL_ADMIN_PASSWORD",
    )

    redis_url: str = Field(
        default="redis://localhost:6379/0",
        alias="REDIS_URL",
    )
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    rate_limit_requests: int = Field(
        default=120, alias="RATE_LIMIT_REQUESTS", ge=10, le=10000
    )
    rate_limit_window_seconds: int = Field(
        default=60, alias="RATE_LIMIT_WINDOW_SECONDS", ge=1, le=3600
    )
    rate_limit_auth_requests: int = Field(
        default=10, alias="RATE_LIMIT_AUTH_REQUESTS", ge=1, le=1000
    )
    rate_limit_auth_window_seconds: int = Field(
        default=300, alias="RATE_LIMIT_AUTH_WINDOW_SECONDS", ge=1, le=3600
    )
    rate_limit_fail_closed: bool = Field(
        default=True, alias="RATE_LIMIT_FAIL_CLOSED"
    )
    metrics_token: SecretStr | None = Field(
        default=None, alias="METRICS_TOKEN"
    )
    default_retention_days: int = Field(
        default=365, alias="DEFAULT_RETENTION_DAYS", ge=1, le=3650
    )
    require_legal_metadata: bool = Field(
        default=False, alias="REQUIRE_LEGAL_METADATA"
    )

    celery_task_always_eager: bool = Field(
        default=False,
        alias="CELERY_TASK_ALWAYS_EAGER",
    )

    osint_http_timeout_seconds: float = Field(
        default=15.0,
        alias="OSINT_HTTP_TIMEOUT_SECONDS",
        gt=0,
        le=60,
    )
    osint_max_response_bytes: int = Field(
        default=2_000_000,
        alias="OSINT_MAX_RESPONSE_BYTES",
        ge=10_000,
        le=20_000_000,
    )
    osint_max_items_per_collector: int = Field(
        default=200,
        alias="OSINT_MAX_ITEMS_PER_COLLECTOR",
        ge=1,
        le=1_000,
    )
    osint_user_agent: str = Field(
        default="OSINT-AI-Framework/0.2 (+local-authorized-research)",
        alias="OSINT_USER_AGENT",
        min_length=10,
        max_length=200,
    )
    soc_sandbox_enabled: bool = Field(
        default=True,
        alias="SOC_SANDBOX_ENABLED",
    )
    soc_sandbox_url: str = Field(
        default="http://sandbox:8090",
        alias="SOC_SANDBOX_URL",
    )
    soc_sandbox_timeout_seconds: float = Field(
        default=20.0,
        alias="SOC_SANDBOX_TIMEOUT_SECONDS",
        gt=0,
        le=60,
    )
    orchestrator_max_tools: int = Field(
        default=40,
        alias="ORCHESTRATOR_MAX_TOOLS",
        ge=1,
        le=50,
    )
    orchestrator_require_ollama: bool = Field(
        default=False,
        alias="ORCHESTRATOR_REQUIRE_OLLAMA",
    )
    osint_search_language: str = Field(
        default="es",
        alias="OSINT_SEARCH_LANGUAGE",
        pattern=r"^[a-z]{2,3}$",
    )
    shodan_api_key: SecretStr | None = Field(
        default=None,
        alias="SHODAN_API_KEY",
    )
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        alias="VIRUSTOTAL_API_KEY",
    )
    securitytrails_api_key: SecretStr | None = Field(
        default=None,
        alias="SECURITYTRAILS_API_KEY",
    )
    urlscan_api_key: SecretStr | None = Field(
        default=None,
        alias="URLSCAN_API_KEY",
    )

    llm_provider: str = Field(default="ollama", alias="LLM_PROVIDER")
    ollama_url: str = Field(
        default="http://localhost:11434",
        alias="OLLAMA_URL",
    )
    ollama_model: str = Field(default="llama3.1:8b", alias="OLLAMA_MODEL")
    rag_embedding_model: str = Field(
        default="nomic-embed-text", alias="RAG_EMBEDDING_MODEL"
    )
    rag_chunk_characters: int = Field(
        default=1600, alias="RAG_CHUNK_CHARACTERS", ge=400, le=8000
    )
    rag_chunk_overlap_characters: int = Field(
        default=240, alias="RAG_CHUNK_OVERLAP_CHARACTERS", ge=0, le=2000
    )
    rag_max_document_characters: int = Field(
        default=500_000,
        alias="RAG_MAX_DOCUMENT_CHARACTERS",
        ge=1_000,
        le=2_000_000,
    )
    rag_max_chunks_per_project: int = Field(
        default=10_000,
        alias="RAG_MAX_CHUNKS_PER_PROJECT",
        ge=100,
        le=100_000,
    )
    rag_embedding_batch_size: int = Field(
        default=32, alias="RAG_EMBEDDING_BATCH_SIZE", ge=1, le=128
    )
    llm_timeout_seconds: float = Field(
        default=120.0,
        alias="LLM_TIMEOUT_SECONDS",
        gt=0,
        le=600,
    )
    llm_max_evidence_characters: int = Field(
        default=50_000,
        alias="LLM_MAX_EVIDENCE_CHARACTERS",
        ge=1_000,
        le=500_000,
    )

    cors_allowed_origins: list[str] = Field(
        default_factory=list,
        alias="CORS_ALLOWED_ORIGINS",
    )
    trusted_hosts: list[str] = Field(
        default_factory=lambda: [
            "localhost",
            "127.0.0.1",
            "api",
            "testserver",
        ],
        alias="TRUSTED_HOSTS",
    )
    smoke_base_url: str = Field(
        default="http://localhost:8000",
        alias="SMOKE_BASE_URL",
    )

    @model_validator(mode="after")
    def reject_production_wildcards(self) -> "Settings":
        """Evita configuraciones CORS/Host permisivas fuera de debug."""

        if not self.debug and (
            "*" in self.cors_allowed_origins
            or "*" in self.trusted_hosts
        ):
            raise ValueError(
                "Wildcards in CORS_ALLOWED_ORIGINS or TRUSTED_HOSTS "
                "require DEBUG=true."
            )
        if self.rag_chunk_overlap_characters >= self.rag_chunk_characters:
            raise ValueError(
                "RAG_CHUNK_OVERLAP_CHARACTERS must be smaller than "
                "RAG_CHUNK_CHARACTERS."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """
    Devuelve una única instancia de Settings.

    lru_cache convierte esta función en un Singleton,
    evitando leer el archivo .env múltiples veces.
    """
    return Settings()


settings = get_settings()
