"""Policy endpoints: list policy candidates for a scan.

Policy candidates are proposals only; applying one requires the approval flow
(safety rule 5: never auto-deploy a generated hardening change).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import get_repositories
from app.domain.errors import NotFoundError
from app.infrastructure.db.repository import Repositories

router = APIRouter(prefix="/api/scans", tags=["policies"])


@router.get("/{scan_id}/policies")
def list_policy_candidates(
    scan_id: str, repos: Repositories = Depends(get_repositories)
) -> dict[str, object]:
    if repos.scans.get(scan_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Scan '{scan_id}' not found.").to_payload(),
        )
    proposal = repos.proposals.latest_for_scan(scan_id)
    candidates = [proposal.policy_candidate] if proposal and proposal.policy_candidate else []
    return {
        "items": [
            {"proposal_id": proposal.proposal_id if proposal else None,
             "candidate": c.model_dump(mode="json")}
            for c in candidates
        ]
    }
