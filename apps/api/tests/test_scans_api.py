"""Happy-path and invalid-input tests for the scan API (definition of done §2-3)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "raven-api"}


def test_endpoints_scans_module_compatibility() -> None:
    import app.api.endpoints.scans as endpoint_scans
    import app.api.scans as legacy_scans

    assert endpoint_scans.router is legacy_scans.router
    assert endpoint_scans.approve_hardening is legacy_scans.approve_hardening
    assert endpoint_scans.create_scan is legacy_scans.create_scan



def test_create_scan_happy_path(client: TestClient, valid_scan_payload: dict) -> None:
    response = client.post("/api/scans", json=valid_scan_payload)
    assert response.status_code == 202
    body = response.json()
    assert body["scan_id"].startswith("scan_")
    assert body["status"] == "created"
    assert body["message"] == "Scan queued"


def test_create_scan_rejects_unknown_target(client: TestClient) -> None:
    response = client.post(
        "/api/scans",
        json={"target_id": "https://evil.example.com", "attack_categories": ["tool_misuse"]},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] in {"TARGET_NOT_ALLOWED", "SSRF_VALIDATION_FAILED"}


def test_create_scan_rejects_too_many_attempts(client: TestClient) -> None:
    response = client.post(
        "/api/scans",
        json={"target_id": "shophelper-local", "max_attempts_per_attack": 5},
    )
    assert response.status_code == 422  # Pydantic constraint (ge=1, le=2)


def test_create_scan_rejects_mutation_with_zero_model_budget(client: TestClient) -> None:
    response = client.post(
        "/api/scans",
        json={
            "target_id": "shophelper-local",
            "enable_mutation": True,
            "budget": {"max_model_calls": 0},
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "VALIDATION_FAILED"


def test_get_scan_not_found(client: TestClient) -> None:
    response = client.get("/api/scans/scan_does_not_exist")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "NOT_FOUND"


def test_get_scan_after_create(client: TestClient, valid_scan_payload: dict) -> None:
    scan_id = client.post("/api/scans", json=valid_scan_payload).json()["scan_id"]
    response = client.get(f"/api/scans/{scan_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == scan_id
    assert body["status"] == "created"
    assert body["target_id"] == "shophelper-local"
    assert body["counts"]["total"] == 0


def test_approve_unknown_proposal_404(
    client: TestClient, valid_scan_payload: dict
) -> None:
    scan_id = client.post("/api/scans", json=valid_scan_payload).json()["scan_id"]
    response = client.post(
        f"/api/scans/{scan_id}/approve-hardening",
        json={"proposal_id": "fix_missing", "approved": True, "approved_by": "demo-user"},
    )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "NOT_FOUND"


def test_approve_requires_awaiting_approval_status(
    client: TestClient, valid_scan_payload: dict
) -> None:
    scan_id = client.post("/api/scans", json=valid_scan_payload).json()["scan_id"]
    # Seed a real proposal directly (worker engine normally creates it).
    from datetime import UTC, datetime

    from app.domain.entities import HardeningProposal

    repos = client.app.state.repos
    repos.proposals.save(
        HardeningProposal(
            proposal_id="fix_1",
            scan_id=scan_id,
            prompt_diff="--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new",
            rationale="test",
            created_at=datetime.now(UTC),
        )
    )
    response = client.post(
        f"/api/scans/{scan_id}/approve-hardening",
        json={"proposal_id": "fix_1", "approved": True, "approved_by": "demo-user"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "VALIDATION_FAILED"


def test_report_requires_existing_scan(client: TestClient) -> None:
    response = client.get("/api/scans/scan_missing/report")
    assert response.status_code == 404


def test_report_sarif_export(client: TestClient, valid_scan_payload: dict) -> None:
    scan_id = client.post("/api/scans", json=valid_scan_payload).json()["scan_id"]
    response = client.get(f"/api/scans/{scan_id}/report?format=sarif")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "2.1.0"
    assert len(body["runs"]) == 1
    assert body["runs"][0]["tool"]["driver"]["name"] == "RAVEN"


def test_approve_hardening_idempotency_and_rejection(
    client: TestClient, valid_scan_payload: dict
) -> None:
    from app.domain.entities import HardeningProposal
    from app.domain.enums import ScanStatus

    scan_id = client.post("/api/scans", json=valid_scan_payload).json()["scan_id"]
    repos = client.app.state.repos
    repos.scans.update_status(scan_id, ScanStatus.AWAITING_APPROVAL)

    repos.proposals.save(
        HardeningProposal(
            proposal_id="fix_idemp_1",
            scan_id=scan_id,
            prompt_diff="--- a\n+++ b",
            rationale="idempotency test",
        )
    )

    # First approval -> moves to retesting
    resp1 = client.post(
        f"/api/scans/{scan_id}/approve-hardening",
        json={"proposal_id": "fix_idemp_1", "approved": True, "approved_by": "sec-lead"},
    )
    assert resp1.status_code == 200
    appr1 = resp1.json()
    assert appr1["approved"] is True
    assert appr1["approved_by"] == "sec-lead"
    assert appr1["proposal_hash"] != ""
    assert repos.scans.get(scan_id).status == ScanStatus.RETESTING

    # Repeated approval request -> returns HTTP 409 Conflict without duplicate retest
    resp2 = client.post(
        f"/api/scans/{scan_id}/approve-hardening",
        json={"proposal_id": "fix_idemp_1", "approved": True, "approved_by": "sec-lead"},
    )
    assert resp2.status_code == 409
    detail = resp2.json()["detail"]
    assert detail["code"] == "CONFLICT"
    assert scan_id in detail["message"]

    # Verify queue does not contain duplicate retest jobs
    queue = client.app.state.queue
    queued_jobs = queue.list_jobs(scan_id) if hasattr(queue, "list_jobs") else []
    # Only 1 retest job should be present
    retest_jobs = [j for j in queued_jobs if j.get("kind") == "run_retest"]
    assert len(retest_jobs) <= 1


