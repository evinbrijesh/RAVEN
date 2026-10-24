"""Shared API test fixtures: temp database + HTTP client."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("RAVEN_EVIDENCE_DIR", str(tmp_path / "evidence"))
    from app.config import get_settings

    get_settings.cache_clear()
    app = create_app()
    # Lifespan (which wires app.state.repos) runs only inside the context.
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def valid_scan_payload() -> dict:
    return {
        "target_id": "shophelper-local",
        "attack_categories": ["direct_injection", "canary_leakage", "sensitive_data", "tool_misuse"],
        "max_attempts_per_attack": 2,
        "enable_mutation": True,
        "run_benign_suite": True,
    }
