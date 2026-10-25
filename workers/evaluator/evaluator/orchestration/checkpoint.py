"""Durable SQLite checkpointer for LangGraph in RAVEN.

Provides thread-safe persistence for graph state across worker restarts
and human approval pauses using the existing SQLite database.
"""

from __future__ import annotations

import random
import sqlite3
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

from app.infrastructure.db.sqlite import Database
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_id,
    get_checkpoint_metadata,
)


class SqliteCheckpointSaver(BaseCheckpointSaver):
    """Durable SQLite checkpointer for LangGraph workflows.

    Integrates with RAVEN's Database instance or raw sqlite3.Connection.
    """

    def __init__(self, db: Database | sqlite3.Connection) -> None:
        super().__init__()
        self._db = db
        self._ensure_tables()

    def _get_connection(self) -> sqlite3.Connection:
        if isinstance(self._db, Database):
            return self._db.connect()
        return self._db

    def _get_lock(self):
        if isinstance(self._db, Database):
            return self._db._lock
        from contextlib import nullcontext
        return nullcontext()

    def _ensure_tables(self) -> None:
        with self._get_lock():
            conn = self._get_connection()
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                thread_id            TEXT NOT NULL,
                checkpoint_ns        TEXT NOT NULL DEFAULT '',
                checkpoint_id        TEXT NOT NULL,
                parent_checkpoint_id TEXT,
                type                 TEXT,
                checkpoint           BLOB,
                metadata_type        TEXT,
                metadata             BLOB,
                PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
            );
            CREATE TABLE IF NOT EXISTS checkpoint_blobs (
                thread_id     TEXT NOT NULL,
                checkpoint_ns TEXT NOT NULL DEFAULT '',
                channel       TEXT NOT NULL,
                version       TEXT NOT NULL,
                type          TEXT,
                blob          BLOB,
                PRIMARY KEY (thread_id, checkpoint_ns, channel, version)
            );
            CREATE TABLE IF NOT EXISTS checkpoint_writes (
                thread_id     TEXT NOT NULL,
                checkpoint_ns TEXT NOT NULL DEFAULT '',
                checkpoint_id TEXT NOT NULL,
                task_id       TEXT NOT NULL,
                idx           INTEGER NOT NULL,
                channel       TEXT NOT NULL,
                type          TEXT,
                blob          BLOB,
                task_path     TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id, task_id, idx)
            );
            """)
            conn.commit()

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id: str = config["configurable"]["thread_id"]
        checkpoint_ns: str = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = get_checkpoint_id(config)

        with self._get_lock():
            conn = self._get_connection()
            cur = conn.cursor()
            if checkpoint_id:
                row = cur.execute(
                    "SELECT checkpoint_id, parent_checkpoint_id, type, checkpoint, metadata_type, metadata "
                    "FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? AND checkpoint_id=?",
                    (thread_id, checkpoint_ns, checkpoint_id),
                ).fetchone()
            else:
                row = cur.execute(
                    "SELECT checkpoint_id, parent_checkpoint_id, type, checkpoint, metadata_type, metadata "
                    "FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? ORDER BY checkpoint_id DESC LIMIT 1",
                    (thread_id, checkpoint_ns),
                ).fetchone()

            if not row:
                return None

            cid, parent_cid, c_type, c_blob, m_type, m_blob = row
            checkpoint_: Checkpoint = self.serde.loads_typed((c_type, c_blob))
            metadata = self.serde.loads_typed((m_type, m_blob))

            writes_rows = cur.execute(
                "SELECT task_id, channel, type, blob FROM checkpoint_writes "
                "WHERE thread_id=? AND checkpoint_ns=? AND checkpoint_id=? ORDER BY task_id, idx",
                (thread_id, checkpoint_ns, cid),
            ).fetchall()
            pending_writes = [
                (t_id, ch, self.serde.loads_typed((t, b)))
                for t_id, ch, t, b in writes_rows
            ]

            channel_values: dict[str, Any] = {}
            for ch, ver in checkpoint_.get("channel_versions", {}).items():
                b_row = cur.execute(
                    "SELECT type, blob FROM checkpoint_blobs "
                    "WHERE thread_id=? AND checkpoint_ns=? AND channel=? AND version=?",
                    (thread_id, checkpoint_ns, ch, str(ver)),
                ).fetchone()
                if b_row:
                    b_type, b_blob = b_row
                    if b_type != "empty":
                        channel_values[ch] = self.serde.loads_typed((b_type, b_blob))

            return CheckpointTuple(
                config={
                    "configurable": {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "checkpoint_id": cid,
                    }
                },
                checkpoint={**checkpoint_, "channel_values": channel_values},
                metadata=metadata,
                parent_config=(
                    {
                        "configurable": {
                            "thread_id": thread_id,
                            "checkpoint_ns": checkpoint_ns,
                            "checkpoint_id": parent_cid,
                        }
                    }
                    if parent_cid
                    else None
                ),
                pending_writes=pending_writes,
            )

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        with self._get_lock():
            conn = self._get_connection()
            cur = conn.cursor()
            query = "SELECT thread_id, checkpoint_ns, checkpoint_id FROM checkpoints WHERE 1=1"
            params: list[Any] = []
            if config:
                query += " AND thread_id=?"
                params.append(config["configurable"]["thread_id"])
                if "checkpoint_ns" in config["configurable"]:
                    query += " AND checkpoint_ns=?"
                    params.append(config["configurable"]["checkpoint_ns"])
            if before and (before_cid := get_checkpoint_id(before)):
                query += " AND checkpoint_id < ?"
                params.append(before_cid)
            query += " ORDER BY checkpoint_id DESC"
            if limit:
                query += f" LIMIT {limit}"
            rows = cur.execute(query, params).fetchall()

        for tid, ns, cid in rows:
            cfg = {"configurable": {"thread_id": tid, "checkpoint_ns": ns, "checkpoint_id": cid}}
            tup = self.get_tuple(cfg)
            if tup:
                if filter and not all(tup.metadata.get(k) == v for k, v in filter.items()):
                    continue
                yield tup

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        c = checkpoint.copy()
        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        values: dict[str, Any] = c.pop("channel_values")

        with self._get_lock():
            conn = self._get_connection()
            cur = conn.cursor()
            for k, v in new_versions.items():
                t, b = self.serde.dumps_typed(values[k]) if k in values else ("empty", b"")
                cur.execute(
                    "INSERT OR REPLACE INTO checkpoint_blobs (thread_id, checkpoint_ns, channel, version, type, blob) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (thread_id, checkpoint_ns, k, str(v), t, b),
                )
            c_type, c_blob = self.serde.dumps_typed(c)
            m_type, m_blob = self.serde.dumps_typed(get_checkpoint_metadata(config, metadata))
            parent_id = config["configurable"].get("checkpoint_id")
            cur.execute(
                "INSERT OR REPLACE INTO checkpoints (thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, type, checkpoint, metadata_type, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (thread_id, checkpoint_ns, checkpoint["id"], parent_id, c_type, c_blob, m_type, m_blob),
            )
            conn.commit()

        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint["id"],
            }
        }

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = config["configurable"]["checkpoint_id"]

        with self._get_lock():
            conn = self._get_connection()
            cur = conn.cursor()
            for idx, (c, v) in enumerate(writes):
                inner_idx = WRITES_IDX_MAP.get(c, idx)
                t, b = self.serde.dumps_typed(v)
                cur.execute(
                    "INSERT OR REPLACE INTO checkpoint_writes (thread_id, checkpoint_ns, checkpoint_id, task_id, idx, channel, type, blob, task_path) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (thread_id, checkpoint_ns, checkpoint_id, task_id, inner_idx, c, t, b, task_path),
                )
            conn.commit()

    def delete_thread(self, thread_id: str) -> None:
        with self._get_lock():
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM checkpoints WHERE thread_id=?", (thread_id,))
            cur.execute("DELETE FROM checkpoint_blobs WHERE thread_id=?", (thread_id,))
            cur.execute("DELETE FROM checkpoint_writes WHERE thread_id=?", (thread_id,))
            conn.commit()

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        return self.get_tuple(config)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        for item in self.list(config, filter=filter, before=before, limit=limit):
            yield item

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        return self.put(config, checkpoint, metadata, new_versions)

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        return self.put_writes(config, writes, task_id, task_path)

    async def adelete_thread(self, thread_id: str) -> None:
        return self.delete_thread(thread_id)

    def get_next_version(self, current: str | None, channel: None) -> str:
        if current is None:
            current_v = 0
        elif isinstance(current, int):
            current_v = current
        else:
            current_v = int(current.split(".")[0])
        next_v = current_v + 1
        next_h = random.random()
        return f"{next_v:032}.{next_h:016}"
