"""Concurrency test: verify multiple scans execute concurrently without contention or state leakage."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest
from app.domain.entities import Scan, ScanConfig
from app.domain.enums import FindingLabel, ScanStatus
from app.domain.value_objects import TargetRef
from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

from evaluator.orchestration.phases import ScanEngine
from evaluator.worker import process_job


@pytest.mark.asyncio
async def test_two_scans_concurrent_execution(repos, fixtures_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    queue = SqliteJobQueue(repos.db)

    # Create two distinct scans
    scan1_id = f"scan_c1_{uuid.uuid4().hex[:6]}"
    scan2_id = f"scan_c2_{uuid.uuid4().hex[:6]}"

    scan1 = Scan(
        scan_id=scan1_id,
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    scan2 = Scan(
        scan_id=scan2_id,
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    repos.scans.create(scan1)
    repos.scans.create(scan2)

    job1 = {"job_id": "job_1", "kind": "run_scan", "payload": {"scan_id": scan1_id}}
    job2 = {"job_id": "job_2", "kind": "run_scan", "payload": {"scan_id": scan2_id}}

    # Execute both jobs concurrently
    await asyncio.gather(
        process_job(repos, job1),
        process_job(repos, job2),
    )

    # Verify both scans completed to AWAITING_APPROVAL cleanly
    updated1 = repos.scans.get(scan1_id)
    updated2 = repos.scans.get(scan2_id)
    assert updated1 is not None and updated1.status == ScanStatus.AWAITING_APPROVAL
    assert updated2 is not None and updated2.status == ScanStatus.AWAITING_APPROVAL

    # Verify findings are isolated to their respective scan IDs
    findings1 = repos.findings.list_for_scan(scan1_id)
    findings2 = repos.findings.list_for_scan(scan2_id)

    assert len(findings1) > 0
    assert len(findings2) > 0
    assert all(f.scan_id == scan1_id for f in findings1)
    assert all(f.scan_id == scan2_id for f in findings2)
