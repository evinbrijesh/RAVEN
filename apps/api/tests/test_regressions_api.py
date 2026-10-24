"""Tests for the regressions API (list, toggle, run)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_list_regressions_seeds_catalog_if_empty(client: TestClient) -> None:
    res = client.get("/api/regressions?target_id=shophelper-local")
    assert res.status_code == 200
    data = res.json()
    assert data["target_id"] == "shophelper-local"
    assert data["total"] > 0
    assert data["active_count"] > 0
    first = data["items"][0]
    assert "regression_id" in first
    assert "attack_case_id" in first
    assert first["active"] is True
    assert "case" in first
    assert "goal" in first["case"]


def test_toggle_regression_case(client: TestClient) -> None:
    # First ensure seeded
    res = client.get("/api/regressions?target_id=shophelper-local")
    items = res.json()["items"]
    reg_id = items[0]["regression_id"]

    # Toggle off
    toggle_res = client.post(f"/api/regressions/{reg_id}/toggle")
    assert toggle_res.status_code == 200
    assert toggle_res.json()["active"] is False

    # Toggle back on
    toggle_res2 = client.post(f"/api/regressions/{reg_id}/toggle")
    assert toggle_res2.status_code == 200
    assert toggle_res2.json()["active"] is True


def test_run_regression_suite_queues_scan(client: TestClient) -> None:
    res = client.post(
        "/api/regressions/run",
        json={"target_id": "shophelper-local"},
    )
    assert res.status_code == 202
    data = res.json()
    assert "scan_id" in data
    assert data["status"] == "created"
