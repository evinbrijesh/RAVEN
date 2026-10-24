"""Control-plane configuration (pydantic-settings over RAVEN_* env vars)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RAVEN_", env_file=".env", extra="ignore")

    env: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = "sqlite:///./data/raven.db"
    redis_url: str = ""
    cors_origins: list[str] = ["http://localhost:3000"]
    evidence_dir: str = "./data/evidence"

    # Model plane
    model_provider: str = "none"
    model_name: str = "meta-llama/llama-3.3-70b-instruct:free"
    model_api_key: str = ""
    model_base_url: str = "https://openrouter.ai/api/v1"

    @property
    def database_path(self) -> str:
        """Extract the filesystem path from the SQLite URL (MVP profile)."""
        prefix = "sqlite:///"
        if self.database_url.startswith(prefix):
            return self.database_url[len(prefix):] or ":memory:"
        # TODO(post-MVP): PostgreSQL URLs require an async engine; the MVP
        # intentionally supports SQLite only (docs/CLAUDE.md defer list).
        raise ValueError(
            f"Unsupported database URL for the MVP profile: {self.database_url}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
