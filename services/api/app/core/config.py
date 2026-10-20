"""Application configuration via environment variables (pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="WARDEN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "warden-api"
    app_version: str = "0.1.0"
    environment: str = "local"

    database_url: str = "sqlite:///./warden.db"
    sql_echo: bool = False

    log_level: str = "INFO"
    log_format: str = "json"

    max_diff_size_bytes: int = 2_000_000
    max_file_size_bytes: int = 1_000_000
    max_files_per_run: int = 200

    github_token: str = ""
    webhook_secret: str = ""

    llm_enabled: bool = False
    llm_provider: str = "openai_compatible"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 20.0
    llm_max_retries: int = 2
    llm_max_tokens_budget: int = 4000

    policy_mode: str = "report"
    block_on: str = "FAIL,ERROR"

    frameworks_dir: str = "frameworks"
    policies_dir: str = "policies"

    demo_seed_database: bool = True
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def sqlalchemy_database_url(self) -> str:
        url = self.database_url
        if url.startswith("sqlite"):
            return url
        if url.startswith("postgres"):
            return url.replace("postgres://", "postgresql+psycopg://", 1)
        return url

    @property
    def block_on_outcomes(self) -> frozenset[str]:
        return frozenset(
            chunk.strip().upper() for chunk in self.block_on.split(",") if chunk.strip()
        )

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
