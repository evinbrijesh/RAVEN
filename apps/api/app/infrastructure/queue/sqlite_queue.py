"""SQLite-backed job queue (durable, works across API/worker processes)."""

from __future__ import annotations

import json
import sqlite3
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
        conn = self._db.connect()
        with self._db._lock:
            try:
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
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
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

    def dead_letter(
        self,
        job_id: str,
        error: str,
        traceback: str | None = None,
    ) -> str:
        """Move an unrecoverable job to the dead-letter queue with full failure forensics."""
        dead_letter_id = f"dl_{uuid.uuid4().hex[:12]}"
        now = _now()
        row = self._db.query_one("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
        if not row:
            return dead_letter_id

        self._db.execute(
            "INSERT INTO job_dead_letters (dead_letter_id, job_id, kind, payload_json,"
            " attempts, error, traceback, dead_lettered_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dead_letter_id,
                job_id,
                row["kind"],
                row["payload_json"],
                row["attempts"],
                error,
                traceback,
                now,
            ),
        )
        self._db.execute(
            "UPDATE jobs SET status = 'failed', error = ?, updated_at = ? WHERE job_id = ?",
            (error, now, job_id),
        )
        return dead_letter_id

    def fail(
        self,
        job_id: str,
        error: str,
        traceback: str | None = None,
        max_attempts: int = 3,
    ) -> None:
        """Mark job failed, escalating to dead-letter queue if max_attempts reached."""
        row = self._db.query_one("SELECT attempts FROM jobs WHERE job_id = ?", (job_id,))
        if row and row["attempts"] >= max_attempts:
            self.dead_letter(job_id, error, traceback)
            return

        self._db.execute(
            "UPDATE jobs SET status = 'failed', error = ?, updated_at = ?"
            " WHERE job_id = ?",
            (error, _now(), job_id),
        )

    def list_dead_letters(self, limit: int = 50) -> list[dict[str, Any]]:
        """List dead-lettered jobs with forensic failure telemetry."""
        rows = self._db.query_all(
            "SELECT * FROM job_dead_letters ORDER BY dead_lettered_at DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "dead_letter_id": r["dead_letter_id"],
                "job_id": r["job_id"],
                "kind": r["kind"],
                "payload": json.loads(r["payload_json"]) if r["payload_json"] else {},
                "attempts": r["attempts"],
                "error": r["error"],
                "traceback": r["traceback"],
                "dead_lettered_at": r["dead_lettered_at"],
            }
            for r in rows
        ]

    def cleanup_stale_jobs(
        self, stale_timeout_seconds: float = 300.0, max_attempts: int = 3
    ) -> list[dict[str, Any]]:
        """Identify and reclaim or fail jobs stuck in 'running' state past stale_timeout_seconds."""
        now_dt = datetime.now(UTC)
        cleaned: list[dict[str, Any]] = []

        conn = self._db.connect()
        with self._db._lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                rows = conn.execute(
                    "SELECT job_id, kind, payload_json, attempts, updated_at FROM jobs WHERE status = 'running'"
                ).fetchall()

                for row in rows:
                    updated_at_str = row["updated_at"]
                    is_stale = False
                    try:
                        updated_dt = datetime.fromisoformat(updated_at_str)
                        if updated_dt.tzinfo is None:
                            updated_dt = updated_dt.replace(tzinfo=UTC)
                        elapsed = (now_dt - updated_dt).total_seconds()
                        if elapsed >= stale_timeout_seconds:
                            is_stale = True
                    except (ValueError, TypeError):
                        is_stale = True

                    if is_stale:
                        job_id = row["job_id"]
                        attempts = row["attempts"]
                        payload = json.loads(row["payload_json"]) if row["payload_json"] else {}

                        if attempts >= max_attempts:
                            dead_letter_id = f"dl_{uuid.uuid4().hex[:12]}"
                            conn.execute(
                                "INSERT INTO job_dead_letters (dead_letter_id, job_id, kind, payload_json,"
                                " attempts, error, traceback, dead_lettered_at)"
                                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (
                                    dead_letter_id,
                                    job_id,
                                    row["kind"],
                                    row["payload_json"],
                                    attempts,
                                    "Worker timeout / orphaned job",
                                    None,
                                    _now(),
                                ),
                            )
                            conn.execute(
                                "UPDATE jobs SET status = 'failed', error = 'Worker timeout / orphaned job', updated_at = ? WHERE job_id = ?",
                                (_now(), job_id),
                            )
                            cleaned.append({
                                "job_id": job_id,
                                "kind": row["kind"],
                                "payload": payload,
                                "action": "failed",
                                "dead_letter_id": dead_letter_id,
                                "attempts": attempts,
                            })
                        else:
                            conn.execute(
                                "UPDATE jobs SET status = 'queued', updated_at = ? WHERE job_id = ?",
                                (_now(), job_id),
                            )
                            cleaned.append({
                                "job_id": job_id,
                                "kind": row["kind"],
                                "payload": payload,
                                "action": "requeued",
                                "attempts": attempts,
                            })

                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

        return cleaned

