"""Scan endpoints: create, get, list, approve-hardening."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.application.approve_hardening import ApproveHardening, GetProposal
from app.application.create_scan import CreateScan
from app.application.get_scan import GetScan
from app.dependencies import get_queue, get_repositories
from app.domain.entities import Approval, HardeningProposal, ScanConfig, ScanView
from app.domain.errors import RavenError
from app.infrastructure.db.repository import Repositories
from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _http_error(exc: RavenError) -> HTTPException:
    if exc.code == "NOT_FOUND":
        http_status = status.HTTP_404_NOT_FOUND
    elif exc.code == "CONFLICT":
        http_status = status.HTTP_409_CONFLICT
    else:
        http_status = status.HTTP_400_BAD_REQUEST
    return HTTPException(status_code=http_status, detail=exc.to_payload())


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    config: ScanConfig,
    repos: Repositories = Depends(get_repositories),
    queue: SqliteJobQueue = Depends(get_queue),
) -> dict[str, str]:
    """Create a scan and queue it for the evaluation worker (202 Accepted)."""
    try:
        scan = CreateScan(repos, queue).execute(config)
    except RavenError as exc:
        raise _http_error(exc) from exc
    return {"scan_id": scan.scan_id, "status": scan.status.value, "message": "Scan queued"}


@router.get("")
def list_scans(
    project_id: str | None = Query(default=None),
    repos: Repositories = Depends(get_repositories),
) -> list[dict[str, str]]:
    scans = repos.scans.list(project_id=project_id)
    return [
        {
            "scan_id": s.scan_id,
            "project_id": s.project_id,
            "status": s.status.value,
            "target_id": s.target.target_id,
        }
        for s in scans
    ]


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    project_id: str | None = Query(default=None),
    repos: Repositories = Depends(get_repositories),
) -> ScanView:
    try:
        return GetScan(repos).execute(scan_id, project_id=project_id)
    except RavenError as exc:
        raise _http_error(exc) from exc



@router.post("/{scan_id}/approve-hardening")
def approve_hardening(
    scan_id: str,
    body: dict[str, object],
    repos: Repositories = Depends(get_repositories),
    queue: SqliteJobQueue = Depends(get_queue),
) -> Approval:
    """Record a human approval decision; only affects the temporary target.

    Duplicate calls return HTTP 409 Conflict without spawning duplicate retest jobs.
    """
    try:
        proposal_id = str(body.get("proposal_id", ""))
        approved = bool(body.get("approved", False))
        approved_by = str(body.get("approved_by", "anonymous"))
        if not proposal_id:
            raise ValueError("proposal_id is required")
        return ApproveHardening(repos, queue).execute(scan_id, proposal_id, approved, approved_by)
    except RavenError as exc:
        raise _http_error(exc) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "VALIDATION_FAILED", "message": str(exc)},
        ) from exc


@router.get("/{scan_id}/proposal")
def get_proposal(
    scan_id: str, repos: Repositories = Depends(get_repositories)
) -> HardeningProposal:
    try:
        return GetProposal(repos).execute(scan_id)
    except RavenError as exc:
        raise _http_error(exc) from exc
