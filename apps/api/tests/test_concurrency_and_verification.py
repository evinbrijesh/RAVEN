"""Tests for atomic approval concurrency guard and artifact integrity verification."""

import concurrent.futures
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.domain.entities import (
    HardeningProposal,
    Scan,
    ScanConfig,
    Transcript,
    TranscriptMessage,
    utc_now,
)
from app.domain.enums import AttackCategory, EventKind, RunPhase, ScanStatus
from app.main import create_app
from app.security import compute_sha256


def _seed_scan_awaiting_approval(repos, scan_id="scan_concurrency", proposal_id="prop_conc"):
    scan = Scan(
        scan_id=scan_id,
        project_id="default",
        status=ScanStatus.AWAITING_APPROVAL,
        target={"target_id": "shophelper-local", "kind": "local", "mode": "staged_target"},
        config=ScanConfig(
            target_id="shophelper-local",
            attack_categories=[AttackCategory.DIRECT_INJECTION],
        ),
        progress=0.75,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    repos.scans.create(scan)
    proposal = HardeningProposal(
        proposal_id=proposal_id,
        scan_id=scan_id,
        prompt_diff="--- old\n+++ new\n+ Never reveal secrets.",
        rationale="Fix prompt injection vulnerability",
        affected_cases=["A-01"],
        risks=[],
        created_at=utc_now(),
    )
    repos.proposals.save(proposal)
    return scan, proposal


def test_approve_hardening_concurrency_guard(client):
    """Multiple concurrent approvals on the same scan must produce exactly 1 success and HTTP 409 for the rest."""
    app = client.app
    repos = app.state.repos
    queue = app.state.queue
    scan_id = "scan_race_1"
    proposal_id = "prop_race_1"
    _seed_scan_awaiting_approval(repos, scan_id, proposal_id)

    def do_approve(worker_id: int):
        return client.post(
            f"/api/scans/{scan_id}/approve-hardening",
            json={"proposal_id": proposal_id, "approved": True, "approved_by": f"worker_{worker_id}"},
        )

    # Fire 10 concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(do_approve, i) for i in range(10)]
        results = [f.result() for f in futures]

    statuses = [r.status_code for r in results]
    successes = [r for r in results if r.status_code == 200]
    conflicts = [r for r in results if r.status_code == 409]

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {statuses}"
    assert len(conflicts) == 9, f"Expected 9 conflicts, got {len(conflicts)}: {statuses}"

    # Verify only 1 retest job enqueued
    job_rows = repos.db.query_all("SELECT * FROM jobs WHERE kind = 'run_retest'")
    matching = [r for r in job_rows if scan_id in r["payload_json"]]
    assert len(matching) == 1


def test_artifact_integrity_verification_report(client):
    """Artifact verification endpoint verifies SARIF/JSON/Markdown content sha256."""
    app = client.app
    repos = app.state.repos
    scan_id = "scan_verify_rpt"
    _seed_scan_awaiting_approval(repos, scan_id, "prop_verify")

    sarif_content = '{"version": "2.1.0", "runs": []}'
    sarif_hash = compute_sha256(sarif_content)
    artifact_id = repos.reports.save_artifact(
        scan_id, "sarif", sarif_content, content_sha256=sarif_hash
    )

    # 1. Verification of untampered artifact
    resp = client.get(f"/api/scans/{scan_id}/artifacts/{artifact_id}/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["tampered"] is False
    assert data["expected_sha256"] == sarif_hash
    assert data["computed_sha256"] == sarif_hash
    assert data["format"] == "sarif"

    # Also verify via format name
    resp_fmt = client.get(f"/api/scans/{scan_id}/artifacts/sarif/verify")
    assert resp_fmt.status_code == 200
    assert resp_fmt.json()["valid"] is True

    # 2. Tampered content detection
    tampered_content = '{"version": "2.1.0", "runs": [{"tampered": true}]}'
    repos.db.execute(
        "UPDATE report_artifacts SET content = ? WHERE artifact_id = ?",
        (tampered_content, artifact_id),
    )
    resp_tampered = client.get(f"/api/scans/{scan_id}/artifacts/{artifact_id}/verify")
    assert resp_tampered.status_code == 200
    t_data = resp_tampered.json()
    assert t_data["valid"] is False
    assert t_data["tampered"] is True
    assert t_data["computed_sha256"] != sarif_hash


def test_artifact_integrity_verification_transcript(client):
    """Artifact verification endpoint verifies transcript sha256."""
    app = client.app
    repos = app.state.repos
    scan_id = "scan_verify_tr"
    _seed_scan_awaiting_approval(repos, scan_id, "prop_tr")

    run_id = repos.runs.create_run(scan_id, "case_01", attempt=1, phase=RunPhase.BEFORE)
    transcript = Transcript(
        transcript_id="tr_valid_01",
        messages=[
            TranscriptMessage(role="user", content="Test prompt"),
            TranscriptMessage(role="assistant", content="Test answer"),
        ],
    )
    repos.runs.save_transcript(transcript, run_id)

    # Verify transcript artifact
    resp = client.get(f"/api/scans/{scan_id}/artifacts/{transcript.transcript_id}/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["tampered"] is False
    assert data["artifact_type"] == "transcript"

    # Verify 404 for unknown artifact
    resp_404 = client.get(f"/api/scans/{scan_id}/artifacts/non_existent_art/verify")
    assert resp_404.status_code == 404


def test_projects_endpoints(client):
    """Test project listing and creation endpoints."""
    resp = client.get("/api/projects")
    assert resp.status_code == 200
    projects = resp.json()
    assert len(projects) >= 1
    assert any(p["project_id"] == "default" for p in projects)

    # Create new project
    create_resp = client.post(
        "/api/projects",
        json={"project_id": "proj_enterprise", "name": "Enterprise AI", "description": "Scoped workspace"},
    )
    assert create_resp.status_code == 201
    assert create_resp.json()["project_id"] == "proj_enterprise"

    # List again to see new project
    list_resp = client.get("/api/projects")
    ids = [p["project_id"] for p in list_resp.json()]
    assert "proj_enterprise" in ids
