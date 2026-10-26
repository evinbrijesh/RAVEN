"""SSE progress stream.

Streams persisted scan_events by polling — works across API/worker processes
without Redis (blueprint §2 MVP simplification). Event names match EventKind.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.dependencies import get_repositories
from app.infrastructure.db.repository import Repositories

router = APIRouter(prefix="/api/scans", tags=["events"])

POLL_INTERVAL_SECONDS = 0.4
TERMINAL_STATUSES = {
    "completed",
    "completed_without_retest",
    "completed_with_limitations",
    "failed_partial",
    "failed_fatal",
    "inconclusive",
}


@router.get("/{scan_id}/events")
@router.get("/{scan_id}/events/stream")
async def stream_events(
    scan_id: str,
    request: Request,
    last_event_id: int | None = None,
    repos: Repositories = Depends(get_repositories),
) -> StreamingResponse:
    if repos.scans.get(scan_id) is None:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Scan '{scan_id}' not found."},
        )

    # Check Last-Event-ID header (standard SSE header) or query parameter
    header_val = request.headers.get("Last-Event-ID")
    resume_from_id = 0
    if last_event_id is not None:
        resume_from_id = last_event_id
    elif header_val:
        try:
            resume_from_id = int(header_val)
        except ValueError:
            resume_from_id = 0

    async def generator():
        curr_event_id = resume_from_id
        while True:
            if await request.is_disconnected():
                break
            events = repos.events.list_since(scan_id, curr_event_id)
            for event in events:
                curr_event_id = event.event_id or curr_event_id
                data = json.dumps(
                    {"event_id": event.event_id, "kind": event.kind.value, **event.payload},
                    default=str,
                )
                yield f"id: {event.event_id}\nevent: {event.kind.value}\ndata: {data}\n\n"
            scan = repos.scans.get(scan_id)
            if scan is not None and scan.status.value in TERMINAL_STATUSES and not events:
                yield (
                    f"event: stream_end\ndata: {json.dumps({'status': scan.status.value})}\n\n"
                )
                break
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}/events/history")
def list_events(
    scan_id: str, repos: Repositories = Depends(get_repositories)
) -> dict[str, object]:
    """Retrieve full persisted event history for a scan over HTTP."""
    if repos.scans.get(scan_id) is None:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Scan '{scan_id}' not found."},
        )
    events = repos.events.list_for_scan(scan_id)
    return {
        "items": [
            {
                "event_id": e.event_id,
                "kind": e.kind.value,
                "created_at": e.created_at.isoformat(),
                **e.payload,
            }
            for e in events
        ]
    }
