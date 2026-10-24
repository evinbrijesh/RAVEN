"""Tests for the promote-regression endpoint (ADR 0001 review gate B5).

Promotion must be scan-scoped, label-restricted, catalog-backed, and
deduplicated per target.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.domain.entities import Finding
from app.domain.enums import AttackCategory, FindingLabel, Severity


def _seed_finding(
    client: TestClient,
    scan_id: str,
    label: FindingLabel,
    attack_id: str = "A-01",
    finding_id: str = "find_1",
) -> None:
    repos = client.app.state.repos
    repos.findings.save(
        Finding(
            finding_id=finding_id,
            scan_id=scan_id,
            attack_id=attack_id,
            category=AttackCategory.DIRECT_INJECTION,
            severity=Severity.HIGH,
            label=label,
            confidence=0.9,
            summary="assistant disclosed the system prompt",
        )
    )


def _create_scan(client: TestClient) -> str:
    return client.post(
        "/api/scans", json={"target_id": "shophelper-local"}
    ).json()["scan_id"]


def test_promote_happy_path_uses_catalog_case(client: TestClient) -> None:
    scan_id = _create_scan(client)
    _seed_finding(client, scan_id, FindingLabel.CONFIRMED_FAILURE)
    response = client.post(
        f"/api/scans/{scan_id}/findings/find_1/promote-regression"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "promoted"
    assert body["attack_id"] == "A-01"
    assert body["target_id"] == "shophelper-local"

    # The persisted case must be the real catalog case, not a stub.
    repos = client.app.state.repos
    active = repos.regressions.list_active("shophelper-local")
    assert len(active) == 1
    case = repos.db.query_one(
        "SELECT case_json FROM regression_cases WHERE regression_id = ?",
        (body["regression_id"],),
    )
    import json

    persisted = json.loads(case["case_json"])
    assert persisted["seed_prompt"], "catalog case must carry the real seed prompt"
    assert persisted["success_rule"], "catalog case must carry the real success rule"


def test_promote_rejects_non_actionable_label(client: TestClient) -> None:
    scan_id = _create_scan(client)
    _seed_finding(client, scan_id, FindingLabel.ATTACK_BLOCKED)
    response = client.post(
        f"/api/scans/{scan_id}/findings/find_1/promote-regression"
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "VALIDATION_FAILED"


def test_promote_rejects_cross_scan_finding(client: TestClient) -> None:
    scan_id = _create_scan(client)
    other_scan_id = _create_scan(client)
    _seed_finding(client, other_scan_id, FindingLabel.CONFIRMED_FAILURE)
    # Finding belongs to other_scan_id; promoting via scan_id must 404.
    response = client.post(
        f"/api/scans/{scan_id}/findings/find_1/promote-regression"
    )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "NOT_FOUND"


def test_promote_rejects_unknown_attack_id(client: TestClient) -> None:
    scan_id = _create_scan(client)
    _seed_finding(client, scan_id, FindingLabel.CONFIRMED_FAILURE, attack_id="A-999")
    response = client.post(
        f"/api/scans/{scan_id}/findings/find_1/promote-regression"
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "VALIDATION_FAILED"


def test_promote_dedupes_per_target(client: TestClient) -> None:
    scan_id = _create_scan(client)
    _seed_finding(client, scan_id, FindingLabel.CONFIRMED_FAILURE)
    first = client.post(f"/api/scans/{scan_id}/findings/find_1/promote-regression")
    assert first.json()["status"] == "promoted"

    # Second promotion of the same attack id returns the existing case.
    _seed_finding(
        client, scan_id, FindingLabel.LIKELY_FAILURE, finding_id="find_2"
    )
    second = client.post(f"/api/scans/{scan_id}/findings/find_2/promote-regression")
    assert second.status_code == 200
    body = second.json()
    assert body["status"] == "already_active"
    assert body["regression_id"] == first.json()["regression_id"]

    repos = client.app.state.repos
    assert len(repos.regressions.list_active("shophelper-local")) == 1


def test_promote_unknown_finding_404(client: TestClient) -> None:
    scan_id = _create_scan(client)
    response = client.post(
        f"/api/scans/{scan_id}/findings/find_missing/promote-regression"
    )
    assert response.status_code == 404
