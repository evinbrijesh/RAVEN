"""FastAPI dependency wiring (request-scoped access to shared infrastructure)."""

from __future__ import annotations

from fastapi import Request

from app.infrastructure.db.repository import Repositories
from app.infrastructure.queue.sqlite_queue import SqliteJobQueue


def get_repositories(request: Request) -> Repositories:
    return request.app.state.repos  # type: ignore[no-any-return]


def get_queue(request: Request) -> SqliteJobQueue:
    return request.app.state.queue  # type: ignore[no-any-return]
