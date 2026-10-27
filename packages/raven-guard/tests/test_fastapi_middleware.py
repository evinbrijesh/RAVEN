"""Tests for FastAPI and Starlette RavenGuardMiddleware."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from raven_guard import (
    PolicyGateway,
    SecurityContext,
    get_current_context,
)
from raven_guard.integrations.fastapi import RavenGuardMiddleware


@pytest.fixture
def gateway():
    return PolicyGateway({
        "version": "v1",
        "fail_closed": True,
        "tools": [
            {
                "tool": "transfer_funds",
                "conditions": [
                    "verified_user_present",
                    "amount_below_threshold",
                ],
                "high_value_action": "human_approval_required",
                "amount_threshold": 100.0,
            },
            {
                "tool": "view_orders",
                "conditions": ["verified_user_present"],
            },
        ],
    })


@pytest.fixture
def app(gateway):
    app = FastAPI()
    app.add_middleware(RavenGuardMiddleware, gateway=gateway)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/me")
    def get_me(request: Request):
        ctx = get_current_context()
        return {
            "user_id": ctx.user_id if ctx else None,
            "roles": ctx.roles if ctx else [],
            "verified_user": ctx.verified_user if ctx else False,
            "tenant_id": ctx.get_claim("tenant_id") if ctx else None,
            "state_user_id": request.state.security_context.user_id,
        }

    @app.post("/api/transfer")
    def transfer(amount: float):
        @gateway.protect(tool="transfer_funds")
        def execute_transfer(amount: float):
            return {"transferred": amount}

        return execute_transfer(amount=amount)

    return app


def test_headers_claims_extraction(app):
    client = TestClient(app)
    headers = {
        "x-user-id": "alice_99",
        "x-tenant-id": "tenant_acme",
        "x-roles": "admin, finance",
        "x-verified-user": "true",
    }

    resp = client.get("/api/me", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == "alice_99"
    assert "admin" in data["roles"]
    assert "finance" in data["roles"]
    assert data["verified_user"] is True
    assert data["tenant_id"] == "tenant_acme"
    assert data["state_user_id"] == "alice_99"


def test_jwt_bearer_claims_extraction(app):
    client = TestClient(app)

    # Construct mock JWT (header.payload.signature)
    payload = {
        "sub": "jwt_user_101",
        "tenant_id": "jwt_tenant",
        "roles": ["developer", "auditor"],
        "verified_user": True,
    }
    header_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    mock_jwt = f"{header_b64}.{payload_b64}.mock_signature"

    resp = client.get("/api/me", headers={"Authorization": f"Bearer {mock_jwt}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == "jwt_user_101"
    assert "developer" in data["roles"]
    assert data["verified_user"] is True
    assert data["tenant_id"] == "jwt_tenant"


def test_excluded_path_bypasses_middleware(app):
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_protected_tool_execution_allowed_in_route(app):
    client = TestClient(app)
    # Verified user and amount below threshold ($50.0 < $100.0)
    resp = client.post(
        "/api/transfer?amount=50.0",
        headers={"x-user-id": "alice", "x-verified-user": "true"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"transferred": 50.0}


def test_policy_violation_returns_403_json(app):
    client = TestClient(app)
    # Missing verified user header
    resp = client.post("/api/transfer?amount=50.0")
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"] == "policy_violation"
    assert data["code"] == "SECURITY_POLICY_VIOLATION"
    assert data["tool"] == "transfer_funds"
    assert data["reason"] == "missing_verified_user"


def test_approval_required_returns_403_json(app):
    client = TestClient(app)
    # Amount $500.0 >= threshold $100.0
    resp = client.post(
        "/api/transfer?amount=500.0",
        headers={"x-user-id": "alice", "x-verified-user": "true"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"] == "approval_required"
    assert data["code"] == "HUMAN_APPROVAL_REQUIRED"
    assert data["tool"] == "transfer_funds"
    assert data["reason"] == "high_value_action:approval_required"


def test_custom_claims_extractor():
    gateway = PolicyGateway({"tools": []})
    app = FastAPI()

    def my_extractor(request: Request) -> SecurityContext:
        return SecurityContext(user_id="custom_extractor_user", verified_user=True)

    app.add_middleware(RavenGuardMiddleware, gateway=gateway, claims_extractor=my_extractor)

    @app.get("/test")
    def test_route():
        ctx = get_current_context()
        return {"user": ctx.user_id if ctx else None}

    client = TestClient(app)
    resp = client.get("/test")
    assert resp.status_code == 200
    assert resp.json() == {"user": "custom_extractor_user"}
