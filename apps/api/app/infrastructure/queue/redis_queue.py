"""Redis-backed job queue stub.

Feature-flagged: only used when RAVEN_REDIS_URL is set. Not implemented in the
MVP (deferred per docs/CLAUDE.md); the interface matches SqliteJobQueue so the
swap is mechanical.
"""

from __future__ import annotations

from typing import Any

from app.domain.errors import RavenError


class RedisQueueNotConfigured(RavenError):
    code = "REDIS_NOT_CONFIGURED"


class RedisJobQueue:
    """Placeholder for the production queue (ARQ/RQ over Redis)."""

    def __init__(self, redis_url: str) -> None:
        # TODO(post-MVP): implement with ARQ or RQ; keep the JobQueue protocol.
        raise RedisQueueNotConfigured(
            "Redis queue is deferred for the MVP; use the SQLite queue.",
            details={"redis_url_set": bool(redis_url)},
        )

    def enqueue(self, kind: str, payload: dict[str, Any]) -> str:  # pragma: no cover
        raise RedisQueueNotConfigured("Redis queue is deferred for the MVP.")

    def claim(self, kinds: tuple[str, ...] = ()) -> dict[str, Any] | None:  # pragma: no cover
        raise RedisQueueNotConfigured("Redis queue is deferred for the MVP.")

    def complete(self, job_id: str) -> None:  # pragma: no cover
        raise RedisQueueNotConfigured("Redis queue is deferred for the MVP.")

    def fail(self, job_id: str, error: str) -> None:  # pragma: no cover
        raise RedisQueueNotConfigured("Redis queue is deferred for the MVP.")
