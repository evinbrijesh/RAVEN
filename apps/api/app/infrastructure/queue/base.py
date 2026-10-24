"""Job queue abstraction.

The MVP uses a SQLite-backed queue so the demo needs no external services
(blueprint §2 "MVP simplification"). The interface is deliberately queue-like
so a Redis-backed implementation can replace it without touching callers.
"""

from __future__ import annotations

from typing import Any, Protocol


class JobQueue(Protocol):
    def enqueue(self, kind: str, payload: dict[str, Any]) -> str: ...
    def claim(self, kinds: tuple[str, ...] = ()) -> dict[str, Any] | None: ...
    def complete(self, job_id: str) -> None: ...
    def fail(self, job_id: str, error: str) -> None: ...
