"""Tests for cross-field context claims matching and structured telemetry."""

from __future__ import annotations

import pytest

from raven_guard import (
    PolicyGateway,
    SecurityContext,
    clear_telemetry_listeners,
)


@pytest.fixture(autouse=True)
def clean_listeners():
    clear_telemetry_listeners()
    yield
    clear_telemetry_listeners()


@pytest.fixture
def claims_policy():
    return {
        "version": "v1",
        "fail_closed": True,
        "tools": [
            {
                "tool": "get_customer_data",
                "conditions": [
                    "verified_user_present",
                    "claims_match:customer_id==user_id",
                ],
            },
            {
                "tool": "modify_billing",
                "conditions": [
                    "tenant_id_matches_context",
                    "account_id_matches_context",
                ],
                "context_claims": {
                    "target_account": "account_id",
                    "tenant_id": "tenant_id",
                },
            },
            {
                "tool": "transfer_ownership",
                "context_claims": {
                    "source_user": "user_id",
                },
            },
        ],
    }


def test_idor_blocked_by_claims_match_condition(claims_policy):
    gw = PolicyGateway(claims_policy)
    ctx = SecurityContext(
        verified_user=True,
        user_id="user_alice",
        claims={"user_id": "user_alice"},
    )

    # 1. Alice accessing her own customer data -> ALLOWED
    dec_alice = gw.authorize("get_customer_data", {"customer_id": "user_alice"}, ctx)
    assert dec_alice.allowed is True

    # 2. Alice attempts IDOR on Bob's customer data -> BLOCKED
    dec_idor = gw.authorize("get_customer_data", {"customer_id": "user_bob"}, ctx)
    assert dec_idor.allowed is False
    assert "claim_mismatch:customer_id!=user_id" in dec_idor.reason


def test_confused_deputy_blocked_by_context_claims_mapping(claims_policy):
    gw = PolicyGateway(claims_policy)
    ctx = SecurityContext(
        verified_user=True,
        claims={
            "account_id": "ACC-100",
            "tenant_id": "tenant-corp-a",
        },
    )

    # 1. Matching target account and tenant -> ALLOWED
    dec_ok = gw.authorize(
        "modify_billing",
        {"target_account": "ACC-100", "tenant_id": "tenant-corp-a", "action": "upgrade"},
        ctx,
    )
    assert dec_ok.allowed is True

    # 2. Confused deputy: Model persuaded to modify another tenant's account -> BLOCKED
    dec_bad_tenant = gw.authorize(
        "modify_billing",
        {"target_account": "ACC-100", "tenant_id": "tenant-corp-b", "action": "upgrade"},
        ctx,
    )
    assert dec_bad_tenant.allowed is False
    assert "claim_mismatch:tenant_id!=tenant_id" in dec_bad_tenant.reason

    # 3. Mismatched target account -> BLOCKED
    dec_bad_account = gw.authorize(
        "modify_billing",
        {"target_account": "ACC-999", "tenant_id": "tenant-corp-a"},
        ctx,
    )
    assert dec_bad_account.allowed is False
    assert "claim_mismatch:target_account!=account_id" in dec_bad_account.reason


def test_missing_required_context_claim_fails_closed(claims_policy):
    gw = PolicyGateway(claims_policy)
    # Context without 'user_id' claim
    ctx_empty = SecurityContext(verified_user=True, claims={})

    dec = gw.authorize("transfer_ownership", {"source_user": "user_123"}, ctx_empty)
    assert dec.allowed is False
    assert "missing_context_claim:user_id" in dec.reason


def test_structured_security_telemetry_event_emission(claims_policy):
    captured_events: list[dict] = []

    gw = PolicyGateway(claims_policy)
    gw.add_telemetry_listener(lambda event: captured_events.append(event))

    ctx = SecurityContext(
        verified_user=True,
        user_id="user_eve",
        claims={"user_id": "user_eve"},
        session_id="sess_attack_01",
    )

    # Trigger blocked IDOR call
    gw.authorize("get_customer_data", {"customer_id": "victim_bob"}, ctx)

    assert len(captured_events) == 1
    event = captured_events[0]
    assert event["event_type"] == "tool_call_blocked"
    assert event["tool"] == "get_customer_data"
    assert event["allowed"] is False
    assert "claim_mismatch:customer_id!=user_id" in event["reason"]
    assert event["user_id"] == "user_eve"
    assert event["session_id"] == "sess_attack_01"
    assert event["arguments"] == {"customer_id": "victim_bob"}
    assert "timestamp" in event


def test_tenant_and_account_condition_helpers():
    gw = PolicyGateway({
        "tools": [
            {
                "tool": "query_tenant_metrics",
                "conditions": [
                    "tenant_id_matches_context",
                    "account_id_matches_context",
                ],
            }
        ]
    })

    ctx = SecurityContext(
        claims={"tenant_id": "t-1", "account_id": "a-1"},
        extra={"tenant_id": "t-1", "account_id": "a-1"},
    )

    # Valid matching
    assert gw.authorize("query_tenant_metrics", {"tenant_id": "t-1", "account_id": "a-1"}, ctx).allowed is True

    # Tenant mismatch
    dec_t = gw.authorize("query_tenant_metrics", {"tenant_id": "t-2", "account_id": "a-1"}, ctx)
    assert dec_t.allowed is False
    assert dec_t.reason == "tenant_id_mismatch"

    # Account mismatch
    dec_a = gw.authorize("query_tenant_metrics", {"tenant_id": "t-1", "account_id": "a-2"}, ctx)
    assert dec_a.allowed is False
    assert dec_a.reason == "account_id_mismatch"
