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


@router.post("/{scan_id}/findings/{finding_id}/promote-regression")
def promote_finding_to_regression(
    scan_id: str,
    finding_id: str,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, str]:
    """Promote a confirmed failure or reviewable finding to a persistent regression case."""
    scan = repos.scans.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Scan '{scan_id}' not found.").to_payload(),
        )
    finding = repos.findings.get(finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Finding '{finding_id}' not found.").to_payload(),
        )

    # Save to regression cases for this target
    from app.domain.entities import AttackCase
    stub_case = AttackCase(
        id=finding.attack_id,
        category=finding.category,
        goal=finding.summary,
        seed_prompt="",
        success_rule="",
        severity=finding.severity,
    )
    reg_id = repos.regressions.save_case(
        target_id=scan.target.target_id,
        attack_case=stub_case,
        case_json=finding.model_dump_json(),
    )
    return {
        "status": "promoted",
        "regression_id": reg_id,
        "attack_id": finding.attack_id,
        "target_id": scan.target.target_id,
    }
