"""RAVEN control plane entrypoint.

The control plane persists state, enqueues work, and streams events. It never
executes target prompts or model calls in the request thread — that is the
evaluation worker's job (blueprint §4 domain boundaries).
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware

from app.api import events, findings, policies, projects, regressions, reports, scans
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
    allow_origins = settings.cors_origins if settings.cors_origins != ["*"] else []
    allow_origin_regex = r".*" if settings.cors_origins == ["*"] else None
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_origin_regex=allow_origin_regex,
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
    app.include_router(projects.router)

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "raven-api"}

    @app.get("/ready", tags=["meta"])
    def ready(response: Response) -> dict[str, object]:
        settings = get_settings()

        # 1. Database check
        db_migrated = False
        db_error = None
        required_tables = ["scans", "findings", "regression_cases", "test_runs", "jobs"]
        found_tables: list[str] = []
        try:
            if hasattr(app.state, "repos") and app.state.repos is not None:
                db = app.state.repos.db
            else:
                db = Database(settings.database_path)
            with db.connect() as conn:
                rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                found_tables = [row["name"] for row in rows]
                if all(t in found_tables for t in required_tables):
                    db_migrated = True
        except (sqlite3.Error, OSError, ValueError) as exc:
            db_error = str(exc)

        # 2. Queue check
        queue_ready = "jobs" in found_tables

        # 3. Fixtures check
        repo_root = Path(__file__).resolve().parents[3]
        fixtures_dir = repo_root / "fixtures" / "shophelper"
        required_fixtures = ["system-prompt.txt", "fake-customers.json", "tools.json"]
        fixtures_present = [f for f in required_fixtures if (fixtures_dir / f).exists()]
        fixtures_ready = len(fixtures_present) == len(required_fixtures)

        # 4. Model configuration status (without exposing secrets)
        model_configured = bool(
            settings.model_provider
            and settings.model_provider != "none"
            and settings.model_api_key
        )
        model_info = {
            "configured": model_configured,
            "provider": settings.model_provider,
            "name": settings.model_name,
        }

        is_ready = db_migrated and queue_ready and fixtures_ready
        if not is_ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

        return {
            "ready": is_ready,
            "status": "ready" if is_ready else "not_ready",
            "database": {
                "migrated": db_migrated,
                "url_kind": settings.database_url.split("://")[0],
                "error": db_error,
            },
            "queue": {
                "ready": queue_ready,
                "kind": "sqlite",
            },
            "fixtures": {
                "ready": fixtures_ready,
                "available": fixtures_present,
            },
            "model": model_info,
        }

    return app


app = create_app()
