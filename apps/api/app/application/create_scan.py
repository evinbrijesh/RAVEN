"""CreateScan use case — POST /api/scans (docs/API_CONTRACT.md §2)."""

from __future__ import annotations

import uuid
from typing import Protocol

from app.domain.entities import Scan, ScanConfig, ScanEvent
from app.domain.enums import EventKind
from app.domain.value_objects import TargetRef
from app.infrastructure.db.repository import Repositories
from app.security.limits import validate_scan_config


class JobQueueLike(Protocol):
    def enqueue(self, kind: str, payload: dict[str, object]) -> str: ...


class CreateScan:
    """Validate, persist, enqueue, and emit. Never runs a scan in-thread."""

    def __init__(self, repos: Repositories, queue: JobQueueLike) -> None:
        self._repos = repos
        self._queue = queue

    def execute(self, config: ScanConfig) -> Scan:
        validated = validate_scan_config(config)
        scan = Scan(
            scan_id=f"scan_{uuid.uuid4().hex[:12]}",
            target=TargetRef(target_id=validated.target_id),
            config=validated,
        )
        self._repos.scans.create(scan)
        self._repos.events.append(
            ScanEvent(
                scan_id=scan.scan_id,
                kind=EventKind.SCAN_CREATED,
                payload={
                    "target_id": scan.target.target_id,
                    "status": scan.status.value,
                },
            )
        )
        self._queue.enqueue("run_scan", {"scan_id": scan.scan_id})
        return scan
