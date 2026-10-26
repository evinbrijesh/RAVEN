"""Regression test suite endpoints: list, toggle, run regression-only scans."""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.application.catalog import load_catalog_cases
from app.application.create_scan import CreateScan
from app.dependencies import get_queue, get_repositories
from app.domain.entities import ScanConfig
from app.domain.errors import NotFoundError, RavenError
from app.infrastructure.db.repository import Repositories
from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

logger = logging.getLogger("raven.api.regressions")

router = APIRouter(prefix="/api/regressions", tags=["regressions"])


class RunRegressionRequest(BaseModel):
    target_id: str = Field(default="shophelper-local")
    project_id: str = Field(default="default")


@router.get("")
def list_regressions(
    target_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    repos: Repositories = Depends(get_repositories),
) -> dict[str, Any]:
    """List persistent regression cases, seeding defaults from catalog if empty."""
    tid = target_id or "shophelper-local"
    items = repos.regressions.list_all(tid, project_id=project_id)

    # If empty, seed initial baseline regression cases from versioned catalog
    if not items and (project_id is None or project_id == "default"):

        try:
            cases = load_catalog_cases()
            # Pick key demonstration attack cases: direct injection, canary leakage, sensitive data, tool misuse
            seed_ids = {"A-01", "A-02", "A-04", "A-08"}
            for case in cases:
                if case.id in seed_ids:
                    repos.regressions.save_case(
                        target_id=tid,
                        attack_case=case,
                        case_json=case.model_dump_json(),
                    )
            items = repos.regressions.list_all(tid)
        except (sqlite3.Error, OSError) as exc:
            logger.warning("Failed to seed baseline regression cases: %s", exc)

    parsed = []
    active_count = 0
    for row in items:
        try:
            case_data = json.loads(row["case_json"])
        except (json.JSONDecodeError, TypeError):
            case_data = {"id": row["attack_case_id"]}
        is_active = bool(row["active"])
        if is_active:
            active_count += 1
        parsed.append(
            {
                "regression_id": row["regression_id"],
                "target_id": row["target_id"],
                "attack_case_id": row["attack_case_id"],
                "active": is_active,
                "created_at": row["created_at"],
                "case": case_data,
            }
        )

    return {
        "target_id": tid,
        "total": len(parsed),
        "active_count": active_count,
        "items": parsed,
    }


@router.post("/{regression_id}/toggle")
def toggle_regression_case(
    regression_id: str,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, Any]:
    updated = repos.regressions.toggle_active(regression_id)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Regression case '{regression_id}' not found.").to_payload(),
        )
    return {
        "regression_id": updated["regression_id"],
        "active": bool(updated["active"]),
        "status": "updated",
    }


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
def run_regression_suite(
    payload: RunRegressionRequest,
    repos: Repositories = Depends(get_repositories),
    queue: SqliteJobQueue = Depends(get_queue),
) -> dict[str, str]:
    """Trigger a regression-only evaluation pass against the target."""
    config = ScanConfig(
        target_id=payload.target_id,
        project_id=payload.project_id,
        regression_only_mode=True,
        run_benign_suite=True,
    )
    try:
        scan = CreateScan(repos, queue).execute(config)
    except RavenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.to_payload(),
        ) from exc
    return {
        "scan_id": scan.scan_id,
        "status": scan.status.value,
        "message": "Regression suite run queued",
    }
