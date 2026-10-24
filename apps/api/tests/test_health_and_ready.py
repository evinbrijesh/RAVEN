"""Tests for /health and /ready readiness contract (Item 13)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "raven-api"}


def test_ready_endpoint_healthy(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["ready"] is True
    assert data["status"] == "ready"
    assert data["database"]["migrated"] is True
    assert data["queue"]["ready"] is True
    assert data["fixtures"]["ready"] is True
    assert "configured" in data["model"]
    # Verify no secrets exposed in model info
    assert "api_key" not in data["model"]
    assert "secret" not in data["model"]


def test_ready_endpoint_unmigrated_returns_503(client: TestClient, monkeypatch) -> None:
    import tempfile

    from app.infrastructure.db.repository import Repositories
    from app.infrastructure.db.sqlite import Database

    # Fresh unmigrated empty sqlite database
    empty_db = Database(tempfile.mktemp(suffix=".db"))
    client.app.state.repos = Repositories(empty_db)

    response = client.get("/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["ready"] is False
    assert data["database"]["migrated"] is False
