"""Event bus abstraction.

Durable events live in scan_events (via EventRepository) and are streamed to
the UI over SSE by polling — this works across processes without Redis.
The in-memory bus exists for in-process subscribers (tests, future fan-out).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import AsyncIterator, Protocol

from app.domain.entities import ScanEvent


class EventBus(Protocol):
    def publish(self, event: ScanEvent) -> None: ...
    def subscribe(self, scan_id: str) -> AsyncIterator[ScanEvent]: ...


class InMemoryEventBus:
    """Per-scan fan-out using asyncio queues (single process only)."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[ScanEvent]]] = defaultdict(list)

    def publish(self, event: ScanEvent) -> None:
        for queue in self._subscribers.get(event.scan_id, []):
            queue.put_nowait(event)

    async def subscribe(self, scan_id: str) -> AsyncIterator[ScanEvent]:
        queue: asyncio.Queue[ScanEvent] = asyncio.Queue()
        self._subscribers[scan_id].append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers[scan_id].remove(queue)
            if not self._subscribers[scan_id]:
                del self._subscribers[scan_id]
