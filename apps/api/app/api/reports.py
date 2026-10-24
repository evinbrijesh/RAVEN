"""Report endpoints: JSON and Markdown export."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse

from app.application.generate_report import GenerateReport
from app.dependencies import get_repositories
from app.domain.errors import RavenError
from app.infrastructure.db.repository import Repositories

router = APIRouter(prefix="/api/scans", tags=["reports"])


@router.get("/{scan_id}/report")
def get_report(
    scan_id: str,
    format: str = "json",
    repos: Repositories = Depends(get_repositories),
):
    if format not in {"json", "markdown"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "VALIDATION_FAILED", "message": "format must be json|markdown"},
        )
    try:
        result = GenerateReport(repos).execute(scan_id, fmt=format)
    except RavenError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=exc.to_payload()
        ) from exc
    if isinstance(result, str):
        return PlainTextResponse(result, media_type="text/markdown")
    return result
