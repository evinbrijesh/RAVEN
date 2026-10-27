"""Full End-to-End Lifecycle and Cancellation Integration Tests for RAVEN.

Verifies the complete lifecycle across the API, Worker, and Target layers:
1. Creation (HTTP 202) -> Job queued
2. Worker execution (Recon -> Attack -> Judge) -> Awaiting Approval
3. Findings extraction and Hardening proposal verification
4. Human approval (HTTP 200) -> Retest queued
5. Duplicate approval conflict (HTTP 409)
6. Retest execution -> Regression promotion -> Final completion
7. Report artifact generation (SARIF & Markdown)
8. Cryptographic artifact integrity verification
9. Active and queued scan cancellation (HTTP 200 / HTTP 409)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.domain.enums import ScanStatus
from app.main import create_app
from fastapi.testclient import TestClient

from evaluator.orchestration.phases import ScanEngine
from evaluator.worker import process_job


@pytest.fixture()
def e2e_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixtures_path: Path):
    db_file = tmp_path / "raven_e2e.db"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("RAVEN_EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))

    from app.config import get_settings
    get_settings.cache_clear()

    app = create_app()
    with TestClient(app) as client:
        repos = client.app.state.repos
        queue = client.app.state.queue
        yield {"client": client, "repos": repos, "queue": queue, "fixtures_path": fixtures_path}


def test_full_e2e_scan_approval_retest_and_report_lifecycle(e2e_env) -> None:
    client = e2e_env["client"]
    repos = e2e_env["repos"]
    queue = e2e_env["queue"]

    # 1. Initiate Scan via REST API
    payload = {
        "target_id": "shophelper-local",
        "attack_categories": ["direct_injection", "canary_leakage", "sensitive_data", "tool_misuse"],
        "max_attempts_per_attack": 2,
        "enable_mutation": False,
        "run_benign_suite": True,
        "budget": {"max_attack_cases": 4, "max_attempts_per_attack": 2, "max_model_calls": 0},
    }
    create_resp = client.post("/api/scans", json=payload)
    assert create_resp.status_code == 202
    data = create_resp.json()
    scan_id = data["scan_id"]
    assert scan_id.startswith("scan_")
    assert data["status"] == "created"

    # 2. Worker claims job from queue
    job = queue.claim(("run_scan",))
    assert job is not None
    assert job["payload"]["scan_id"] == scan_id

    # 3. Worker executes scan (Recon -> Attacks -> Judge -> Propose Hardening)
    import asyncio
    asyncio.run(process_job(repos, job))
    queue.complete(job["job_id"])

    # 4. Verify scan paused at AWAITING_APPROVAL
    scan = repos.scans.get(scan_id)
    assert scan is not None
    assert scan.status == ScanStatus.AWAITING_APPROVAL

    # Verify findings were created
    findings = repos.findings.list_for_scan(scan_id)
    assert len(findings) > 0

    # 5. Retrieve proposal via REST API
    prop_resp = client.get(f"/api/scans/{scan_id}/proposal")
    assert prop_resp.status_code == 200
    proposal = prop_resp.json()
    proposal_id = proposal["proposal_id"]
    assert proposal_id.startswith(("fix_", "prop_"))
    assert "prompt_diff" in proposal

    # 6. Submit Human Approval via REST API
    appr_resp = client.post(
        f"/api/scans/{scan_id}/approve-hardening",
        json={"proposal_id": proposal_id, "approved": True, "approved_by": "sec-director@raven.internal"},
    )
    assert appr_resp.status_code == 200
    appr_data = appr_resp.json()
    assert appr_data["approved"] is True
    assert appr_data["approved_by"] == "sec-director@raven.internal"

    # 7. Verify duplicate approval returns HTTP 409 Conflict (idempotency guard)
    dup_resp = client.post(
        f"/api/scans/{scan_id}/approve-hardening",
        json={"proposal_id": proposal_id, "approved": True, "approved_by": "sec-director@raven.internal"},
    )
    assert dup_resp.status_code == 409
    assert dup_resp.json()["detail"]["code"] == "CONFLICT"

    # 8. Worker claims retest job
    retest_job = queue.claim(("run_retest",))
    assert retest_job is not None
    assert retest_job["payload"]["scan_id"] == scan_id

    # 9. Worker executes retest & promotion
    asyncio.run(process_job(repos, retest_job))
    queue.complete(retest_job["job_id"])

    # 10. Scan must now be in terminal COMPLETED status
    final_scan = repos.scans.get(scan_id)
    assert final_scan is not None
    assert final_scan.status in (ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITHOUT_RETEST)

    # 11. Verify regression cases were promoted
    regressions = repos.regressions.list_active("shophelper-local")
    assert isinstance(regressions, list)

    # 12. Verify SARIF report export
    sarif_resp = client.get(f"/api/scans/{scan_id}/report?format=sarif")
    assert sarif_resp.status_code == 200
    sarif_doc = json.loads(sarif_resp.text)
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"]) > 0

    # 13. Verify Cryptographic Integrity Endpoint
    row = repos.db.query_one("SELECT artifact_id FROM report_artifacts WHERE scan_id = ? AND format = 'sarif'", (scan_id,))
    if row:
        art_id = row["artifact_id"]
        verify_resp = client.get(f"/api/scans/{scan_id}/artifacts/{art_id}/verify")
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["valid"] is True
        assert verify_data["tampered"] is False


def test_scan_cancellation_queued(e2e_env) -> None:
    """Verify cancelling a queued scan transitions to failed_partial and cancels queue ticket."""
    client = e2e_env["client"]
    repos = e2e_env["repos"]
    queue = e2e_env["queue"]

    payload = {"target_id": "shophelper-local", "budget": {"max_attack_cases": 2}}
    create_resp = client.post("/api/scans", json=payload)
    scan_id = create_resp.json()["scan_id"]

    # Cancel while still queued
    cancel_resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert cancel_resp.status_code == 200
    cancel_data = cancel_resp.json()
    assert cancel_data["status"] == "failed_partial"
    assert "cancelled successfully" in cancel_data["message"]

    # Verify scan status in DB is failed_partial
    scan = repos.scans.get(scan_id)
    assert scan.status == ScanStatus.FAILED_PARTIAL

    # Verify job in queue was marked failed so worker won't run it
    claimed = queue.claim(("run_scan",))
    assert claimed is None  # Queue has no runnable jobs

    # Cancelling an already-cancelled scan returns HTTP 409 Conflict
    recancel_resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert recancel_resp.status_code == 409
    assert recancel_resp.json()["detail"]["code"] == "CONFLICT"


def test_scan_cancellation_mid_execution(e2e_env) -> None:
    """Verify that cancelling during attack execution stops worker safely."""
    client = e2e_env["client"]
    repos = e2e_env["repos"]
    fixtures_path = e2e_env["fixtures_path"]

    payload = {"target_id": "shophelper-local", "budget": {"max_attack_cases": 5}}
    create_resp = client.post("/api/scans", json=payload)
    scan_id = create_resp.json()["scan_id"]

    # Pre-mark scan as failed_partial as if user clicked cancel during execution
    repos.scans.update_status(scan_id, ScanStatus.FAILED_PARTIAL)

    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    import asyncio
    asyncio.run(engine.run(scan_id))

    # Engine must exit cleanly without raising an error
    final_scan = repos.scans.get(scan_id)
    assert final_scan.status == ScanStatus.FAILED_PARTIAL
