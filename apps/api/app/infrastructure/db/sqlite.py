"""SQLite connection and migration helper.

MVP profile uses SQLite (blueprint §2 "MVP simplification"). The repository
layer is intentionally storage-agnostic so PostgreSQL can replace it without
touching domain or application code.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class Database:
    """Small synchronous SQLite wrapper with per-thread connections."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = Lock()
        if self.path != Path(":memory:"):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._shared: sqlite3.Connection | None = None
        if self.path == Path(":memory:"):
            # :memory: databases are per-connection; keep one shared connection
            # so tests can use an in-memory database safely.
            self._shared = self._new_connection()

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def connect(self) -> sqlite3.Connection:
        with self._lock:
            if self._shared is not None:
                return self._shared
            return self._new_connection()

    def migrate(self) -> None:
        """Apply the canonical schema (idempotent, CREATE IF NOT EXISTS)."""
        ddl = SCHEMA_PATH.read_text(encoding="utf-8")
        with self._lock:
            conn = self.connect()
            conn.executescript(ddl)
            conn.commit()

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
