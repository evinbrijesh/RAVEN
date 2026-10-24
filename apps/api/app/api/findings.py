"""Findings endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import get_repositories
from app.domain.entities import Finding
from app.domain.errors import NotFoundError
from app.infrastructure.db.repository import Repositories

router = APIRouter(prefix="/api/scans", tags=["findings"])


@router.get("/{scan_id}/findings")
def list_findings(
    scan_id: str, repos: Repositories = Depends(get_repositories)
) -> dict[str, object]:
    if repos.scans.get(scan_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Scan '{scan_id}' not found.").to_payload(),
        )
    findings: list[Finding] = repos.findings.list_for_scan(scan_id)
    return {"items": [f.model_dump(mode="json") for f in findings]}
