"""SQLite-backed job queue (durable, works across API/worker processes)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from app.infrastructure.db.sqlite import Database


def _now() -> str:
    return datetime.now(UTC).isoformat()


class SqliteJobQueue:
    def __init__(self, db: Database) -> None:
        self._db = db

    def enqueue(self, kind: str, payload: dict[str, Any]) -> str:
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        self._db.execute(
            "INSERT INTO jobs (job_id, kind, payload_json, status, created_at,"
            " updated_at) VALUES (?, ?, ?, 'queued', ?, ?)",
            (job_id, kind, json.dumps(payload, default=str), _now(), _now()),
        )
        return job_id

    def claim(self, kinds: tuple[str, ...] = ()) -> dict[str, Any] | None:
        """Atomically claim the oldest queued job (optionally filtered by kind)."""
        placeholders = ",".join("?" for _ in kinds) if kinds else None
        sql = (
            "SELECT * FROM jobs WHERE status = 'queued'"
            + (f" AND kind IN ({placeholders})" if placeholders else "")
            + " ORDER BY created_at LIMIT 1"
        )
        params = tuple(kinds) if kinds else ()
        with self._db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(sql, params).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            conn.execute(
                "UPDATE jobs SET status = 'running', attempts = attempts + 1,"
                " updated_at = ? WHERE job_id = ?",
                (_now(), row["job_id"]),
            )
            conn.execute("COMMIT")
        return {
            "job_id": row["job_id"],
            "kind": row["kind"],
            "payload": json.loads(row["payload_json"]),
            "attempts": row["attempts"] + 1,
        }

    def complete(self, job_id: str) -> None:
        self._db.execute(
            "UPDATE jobs SET status = 'done', updated_at = ? WHERE job_id = ?",
            (_now(), job_id),
        )

    def fail(self, job_id: str, error: str) -> None:
        self._db.execute(
            "UPDATE jobs SET status = 'failed', error = ?, updated_at = ?"
            " WHERE job_id = ?",
            (error, _now(), job_id),
        )
