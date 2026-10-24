"""Worker configuration (RAVEN_* env vars, same database as the control plane)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from app.config import Settings as ApiSettings
from app.config import get_settings as get_api_settings


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


class WorkerSettings(ApiSettings):
    """Worker shares the API settings schema plus worker-specific knobs."""

    worker_concurrency: int = 2
    poll_interval_seconds: float = 0.5
    fixtures_dir: str = ""

    @property
    def fixtures_path(self) -> Path:
        return Path(self.fixtures_dir) if self.fixtures_dir else repo_root() / "fixtures" / "shophelper"


def clear_settings_cache() -> None:
    get_api_settings.cache_clear()
    get_worker_settings.cache_clear()


@lru_cache
def get_worker_settings() -> WorkerSettings:
    # Reuse the API settings loader (same env prefix) and overlay defaults.
    api: ApiSettings = get_api_settings()
    settings = WorkerSettings(
        env=api.env,
        api_host=api.api_host,
        api_port=api.api_port,
        database_url=api.database_url,
        redis_url=api.redis_url,
        cors_origins=api.cors_origins,
        evidence_dir=api.evidence_dir,
        model_provider=api.model_provider,
        model_name=api.model_name,
        model_api_key=api.model_api_key,
        model_base_url=api.model_base_url,
    )
    if "RAVEN_WORKER_CONCURRENCY" in os.environ:
        settings.worker_concurrency = int(os.environ["RAVEN_WORKER_CONCURRENCY"])
    if "RAVEN_FIXTURES_DIR" in os.environ:
        settings.fixtures_dir = os.environ["RAVEN_FIXTURES_DIR"]
    return settings

