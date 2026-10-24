"""Control-plane configuration (pydantic-settings over RAVEN_* env vars)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = REPO_ROOT / ".env" if (REPO_ROOT / ".env").exists() else ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RAVEN_",
        env_file=str(ENV_FILE),
        extra="ignore",
    )

    env: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = "sqlite:///./data/raven.db"
    redis_url: str = ""
    cors_origins: list[str] | str = ["*"]
    evidence_dir: str = "./data/evidence"

    @field_validator("cors_origins", mode="after")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                import json

                return json.loads(v)
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


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
