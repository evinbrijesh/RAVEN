"""SQLite connection and migration helper.

MVP profile uses SQLite (blueprint §2 "MVP simplification"). The repository
layer is intentionally storage-agnostic so PostgreSQL can replace it without
touching domain or application code.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class Database:
    """SQLite wrapper with ONE shared connection guarded by an RLock.

    A single connection eliminates SQLite file-lock contention between the
    API and worker threads (both processes open their own Database instance
    on the same file; WAL mode keeps cross-process access safe).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = RLock()
        if self.path != Path(":memory:"):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._shared: sqlite3.Connection = self._new_connection()

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def connect(self) -> sqlite3.Connection:
        with self._lock:
            return self._shared

    def migrate(self) -> None:
        """Apply the canonical schema (idempotent, CREATE IF NOT EXISTS)."""
        ddl = SCHEMA_PATH.read_text(encoding="utf-8")
        with self._lock:
            conn = self.connect()
            self._add_missing_columns(conn)
            conn.executescript(ddl)
            self._add_unique_indexes(conn)
            conn.commit()

    @staticmethod
    def _add_unique_indexes(conn: sqlite3.Connection) -> None:
        """Create unique indexes defensively.

        A pre-existing database may contain duplicate rows that violate the
        index; in that case skip creation rather than failing startup (the
        application-layer dedupe still applies).
        """
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_regression_cases_active"
                " ON regression_cases(target_id, attack_case_id) WHERE active = 1"
            )
        except sqlite3.IntegrityError:
            pass

    @staticmethod
    def _add_missing_columns(conn: sqlite3.Connection) -> None:
        """Additive migrations for databases created before a column existed.

        schema.sql uses CREATE TABLE IF NOT EXISTS, so pre-existing files never
        gain new columns from it. Each entry: (table, column, DDL fragment).
        """
        existing_tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        additions: list[tuple[str, str, str]] = [
            ("scans", "completed_at", "TEXT"),
            ("verdicts", "llm_model_name", "TEXT"),
            ("verdicts", "llm_prompt_version", "TEXT"),
            ("report_artifacts", "schema_version", "TEXT NOT NULL DEFAULT '1.0'"),
            ("report_artifacts", "generator_version", "TEXT NOT NULL DEFAULT ''"),
            ("report_artifacts", "content_sha256", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "weak_point_json", "TEXT"),
        ]
        for table, column, ddl_type in additions:
            if table not in existing_tables:
                continue
            existing = {
                row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock:
            conn = self.connect()
            conn.execute(sql, params)
            conn.commit()

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            conn = self.connect()
            return list(conn.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            conn = self.connect()
            return conn.execute(sql, params).fetchone()
