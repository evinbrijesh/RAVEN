"""Soak and Concurrency Reliability Test Suite for RAVEN (Week 1 Gate).

Verifies:
1. 10 consecutive full scan -> approval -> retest -> report lifecycles on a single DB without failure.
2. Concurrent multi-scan execution under multi-worker concurrency with isolated findings.
3. Unhandled worker process crash cleanly transitions scan to FAILED_FATAL without wedging jobs.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from app.config import get_settings
from app.domain.enums import ScanStatus
from app.main import create_app
from fastapi.testclient import TestClient

from evaluator.worker import _worker_slot, process_job


@pytest.fixture
def soak_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixtures_path: Path):
    db_file = tmp_path / "raven_soak.db"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("RAVEN_EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))

    get_settings.cache_clear()

    app = create_app()
    with TestClient(app) as client:
        repos = client.app.state.repos
        queue = client.app.state.queue
        yield {
            "client": client,
            "repos": repos,
            "queue": queue,
            "fixtures_path": fixtures_path,
        }


def test_10_consecutive_scan_approval_lifecycles(soak_env) -> None:
    """Week 1 Quality Gate: 10 consecutive full scan, approval, and report lifecycles

    must execute reliably with zero errors, zero DB locks, and zero state corruption.
    """
    client = soak_env["client"]
    repos = soak_env["repos"]
    queue = soak_env["queue"]

    for cycle in range(1, 11):
        # 1. Create Scan
        payload = {
            "target_id": "shophelper-local",
            "attack_categories": ["direct_injection", "canary_leakage"],
            "max_attempts_per_attack": 1,
            "enable_mutation": False,
            "budget": {"max_attack_cases": 2, "max_model_calls": 0},
        }
        create_resp = client.post("/api/scans", json=payload)
        assert create_resp.status_code == 202, f"Cycle {cycle}: Create scan failed"
        scan_id = create_resp.json()["scan_id"]

        # 2. Worker executes scan
        job = queue.claim(["run_scan"])
        assert job is not None, f"Cycle {cycle}: Expected queued run_scan job"
        assert job["payload"]["scan_id"] == scan_id

        asyncio.run(process_job(repos, job))
        queue.complete(job["job_id"])

        scan_after_attack = repos.scans.get(scan_id)
        assert scan_after_attack is not None
        assert scan_after_attack.status == ScanStatus.AWAITING_APPROVAL, (
            f"Cycle {cycle}: Expected AWAITING_APPROVAL, got {scan_after_attack.status}"
        )

        proposal = repos.proposals.latest_for_scan(scan_id)
        assert proposal is not None, f"Cycle {cycle}: Expected proposal for scan {scan_id}"

        # 3. Approve hardening
        approval_resp = client.post(
            f"/api/scans/{scan_id}/approve-hardening",
            json={
                "proposal_id": proposal.proposal_id,
                "approved": True,
                "approved_by": f"qa_lead_cycle_{cycle}",
            },
        )
        assert approval_resp.status_code == 200, f"Cycle {cycle}: Approval failed"

        # 4. Worker executes retest
        retest_job = queue.claim(["run_retest"])
        assert retest_job is not None, f"Cycle {cycle}: Expected queued run_retest job"
        assert retest_job["payload"]["scan_id"] == scan_id

        asyncio.run(process_job(repos, retest_job))
        queue.complete(retest_job["job_id"])

        # 5. Verify terminal status
        completed_scan = repos.scans.get(scan_id)
        assert completed_scan.status == ScanStatus.COMPLETED, (
            f"Cycle {cycle}: Expected COMPLETED, got {completed_scan.status}"
        )

        # 6. Verify SARIF report generation
        sarif_resp = client.get(f"/api/scans/{scan_id}/report?format=sarif")
        assert sarif_resp.status_code == 200, f"Cycle {cycle}: Failed to get SARIF report"
        sarif_data = sarif_resp.json()
        assert sarif_data["version"] == "2.1.0"


@pytest.mark.asyncio
async def test_concurrent_scans_under_multi_worker_concurrency(soak_env) -> None:
    """Verifies that multiple concurrent scans run simultaneously without SQLite contention

    or finding bleed between jobs.
    """
    client = soak_env["client"]
    repos = soak_env["repos"]
    queue = soak_env["queue"]

    scan_ids = []
    # 1. Enqueue 3 independent scans concurrently
    for i in range(3):
        resp = client.post(
            "/api/scans",
            json={
                "target_id": "shophelper-local",
                "attack_categories": ["direct_injection", "canary_leakage"],
                "max_attempts_per_attack": 1,
                "enable_mutation": False,
                "budget": {"max_attack_cases": 2, "max_model_calls": 0},
            },
        )
        assert resp.status_code == 202
        scan_ids.append(resp.json()["scan_id"])

    # 2. Claim all 3 jobs
    jobs = []
    for _ in range(3):
        job = queue.claim(["run_scan"])
        assert job is not None
        jobs.append(job)

    # 3. Execute all 3 jobs concurrently in parallel using asyncio.gather
    results = await asyncio.gather(
        *(process_job(repos, j) for j in jobs),
        return_exceptions=True,
    )

    # Assert no exceptions raised during parallel execution
    for res in results:
        if isinstance(res, Exception):
            raise res

    for j in jobs:
        queue.complete(j["job_id"])

    # 4. Verify each scan reached AWAITING_APPROVAL and has distinct isolated findings
    for sid in scan_ids:
        scan = repos.scans.get(sid)
        assert scan is not None
        assert scan.status == ScanStatus.AWAITING_APPROVAL

        # Findings must belong strictly to this scan_id
        findings = repos.findings.list_for_scan(sid)
        for f in findings:
            assert f.scan_id == sid


@pytest.mark.asyncio
async def test_worker_slot_unhandled_exception_marks_scan_failed_fatal(soak_env) -> None:
    """If an unhandled exception crashes a worker task, the scan must be transitioned

    to FAILED_FATAL and the job marked failed.
    """
    repos = soak_env["repos"]
    queue = soak_env["queue"]

    # Enqueue a test scan
    scan_id = "scan_crash_test_1"
    from app.domain.entities import Scan, ScanConfig, TargetRef
    scan = Scan(
        scan_id=scan_id,
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    repos.scans.create(scan)
    repos.scans.update_status(scan_id, ScanStatus.ATTACKING)

    job_id = queue.enqueue("run_scan", {"scan_id": scan_id})
    job = queue.claim(["run_scan"])
    assert job is not None
    assert job["job_id"] == job_id

    semaphore = asyncio.Semaphore(1)
    active_tasks: set[asyncio.Task] = set()

    # We simulate a catastrophic unhandled engine exception by monkeypatching process_job
    import evaluator.worker as worker_mod
    original_process = worker_mod.process_job

    async def mock_crashing_process(r, j):
        raise RuntimeError("Catastrophic worker memory failure")

    worker_mod.process_job = mock_crashing_process
    try:
        await _worker_slot(semaphore, repos, job, active_tasks)
    finally:
        worker_mod.process_job = original_process

    # Verify job is failed
    job_row = repos.db.query_one("SELECT status, error FROM jobs WHERE job_id = ?", (job_id,))
    assert job_row is not None
    assert job_row["status"] == "failed"
    assert "Catastrophic worker memory failure" in job_row["error"]

    # Verify scan is marked FAILED_FATAL
    updated_scan = repos.scans.get(scan_id)
    assert updated_scan is not None
    assert updated_scan.status == ScanStatus.FAILED_FATAL
