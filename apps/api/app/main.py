"""RAVEN control plane entrypoint.

The control plane persists state, enqueues work, and streams events. It never
executes target prompts or model calls in the request thread — that is the
evaluation worker's job (blueprint §4 domain boundaries).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import events, findings, policies, regressions, reports, scans
from app.config import Settings, get_settings
from app.infrastructure.db.repository import Repositories
from app.infrastructure.db.sqlite import Database
from app.infrastructure.queue.sqlite_queue import SqliteJobQueue
from app.infrastructure.storage.local import LocalEvidenceStore
from app.security.redaction import redact

logger = logging.getLogger("raven.api")


class RedactingHandler(logging.Handler):
    """Logging handler that redacts sensitive patterns (safety rule 10)."""

    def emit(self, record: logging.LogRecord) -> None:
        record.msg = redact(str(record.msg))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = get_settings()
    db = Database(settings.database_path)
    db.migrate()
    app.state.repos = Repositories(db)
    app.state.queue = SqliteJobQueue(db)
    app.state.evidence_store = LocalEvidenceStore(settings.evidence_dir)
    logger.info("RAVEN control plane ready (env=%s, db=%s)", settings.env, settings.database_path)
    yield
    app.state.repos = None


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="RAVEN Control Plane",
        version="0.1.0",
        description="Bounded, human-supervised security regression for LLM applications.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(policies.router)
    app.include_router(regressions.router)
    app.include_router(reports.router)
    app.include_router(events.router)

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "raven-api"}

    @app.get("/ready", tags=["meta"])
    def ready() -> dict[str, object]:
        db_ok = Path(settings.database_path).exists() or settings.database_path.startswith("sqlite:///")
        return {"ready": db_ok, "queue": "sqlite", "database": settings.database_url.split("://")[0]}

    return app


app = create_app()
