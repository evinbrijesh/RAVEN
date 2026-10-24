"""Comprehensive tests for the fail-closed PolicyGateway (ADR requirement 8)."""

from __future__ import annotations

import pytest

from evaluator.targets.base import ToolContext
from evaluator.targets.policy_gateway import PolicyGateway


@pytest.fixture
def base_policy():
    return {
        "version": "test-v1",
        "fail_closed": True,
        "tools": [
            {
                "tool": "issue_refund",
                "conditions": [
                    "verified_order_id_present",
                    "verified_user_present",
                    "amount_below_threshold",
                ],
                "high_value_action": "human_approval_required",
                "amount_threshold": 100.0,
                "on_violation": "deny_and_log",
            },
            {
                "tool": "get_order",
                "conditions": ["verified_order_id_present"],
                "high_value_action": "none",
                "on_violation": "deny_and_log",
            },
        ],
    }


def test_unknown_tool_denied(base_policy):
    gateway = PolicyGateway(base_policy)
    ctx = ToolContext(
        user_message="delete all accounts",
        order_id="1001",
        amount=0.0,
        verified_order_id=True,
        verified_user=True,
    )
    decision = gateway.authorize("unknown_administrative_tool", {"action": "purge"}, ctx)
    assert not decision.allowed
    assert "no_policy_for_tool" in decision.reason


def test_missing_policy_denied():
    gateway = PolicyGateway({"tools": []})
    ctx = ToolContext(
        user_message="refund me",
        order_id="1001",
        amount=25.0,
        verified_order_id=True,
        verified_user=True,
    )
    decision = gateway.authorize("issue_refund", {"order_id": "1001", "amount": 25.0}, ctx)
    assert not decision.allowed
    assert "no_policy_for_tool" in decision.reason


def test_missing_verification_denied(base_policy):
    gateway = PolicyGateway(base_policy)
    # Context without verified user
    ctx_unverified_user = ToolContext(
        user_message="Issue refund for order 1001",
        order_id="1001",
        amount=25.0,
        verified_order_id=True,
        verified_user=False,
    )
    decision = gateway.authorize(
        "issue_refund", {"order_id": "1001", "amount": 25.0}, ctx_unverified_user
    )
    assert not decision.allowed
    assert decision.reason == "missing_verified_user"

    # Context without verified order
    ctx_unverified_order = ToolContext(
        user_message="Issue refund",
        order_id="",
        amount=25.0,
        verified_order_id=False,
        verified_user=True,
    )
    decision_order = gateway.authorize(
        "issue_refund", {"amount": 25.0}, ctx_unverified_order
    )
    assert not decision_order.allowed
    assert decision_order.reason == "missing_verified_order_id"


def test_high_value_action_approval_required(base_policy):
    gateway = PolicyGateway(base_policy)
    # Amount is $500 which is >= threshold of $100
    ctx = ToolContext(
        user_message="Issue large refund",
        order_id="1001",
        amount=500.0,
        verified_order_id=True,
        verified_user=True,
    )
    decision = gateway.authorize(
        "issue_refund", {"order_id": "1001", "amount": 500.0}, ctx
    )
    assert not decision.allowed
    assert decision.reason == "high_value_action:approval_required"


def test_valid_verified_action_allowed(base_policy):
    gateway = PolicyGateway(base_policy)
    # Valid verified user, verified order, and amount $25.0 < $100.0
    ctx = ToolContext(
        user_message="Issue valid small refund",
        order_id="1001",
        amount=25.0,
        verified_order_id=True,
        verified_user=True,
    )
    decision = gateway.authorize(
        "issue_refund", {"order_id": "1001", "amount": 25.0}, ctx
    )
    assert decision.allowed
    assert decision.reason == "all_conditions_met"


def test_malformed_arguments_denied(base_policy):
    gateway = PolicyGateway(base_policy)
    ctx = ToolContext(
        user_message="test",
        order_id="1001",
        amount=25.0,
        verified_order_id=True,
        verified_user=True,
    )
    # 1. Non-dict arguments
    decision_non_dict = gateway.authorize("issue_refund", "not-a-dict", ctx)  # type: ignore
    assert not decision_non_dict.allowed
    assert "malformed_arguments" in decision_non_dict.reason

    # 2. Negative amount
    decision_neg = gateway.authorize("issue_refund", {"order_id": "1001", "amount": -50.0}, ctx)
    assert not decision_neg.allowed
    assert decision_neg.reason == "malformed_arguments:negative_amount"

    # 3. Invalid amount type
    decision_invalid_type = gateway.authorize("issue_refund", {"order_id": "1001", "amount": "abc"}, ctx)
    assert not decision_invalid_type.allowed
    assert decision_invalid_type.reason == "malformed_arguments:invalid_amount_type"


def test_policy_reload_between_scans_no_leakage(base_policy):
    gateway = PolicyGateway(base_policy)

    # Apply candidate rule for scan 1
    candidate = {
        "tool": "get_order",
        "conditions": ["verified_user_present"],
        "high_value_action": "none",
    }
    gateway.apply_candidate(candidate)
    assert "verified_user_present" in gateway._policies["get_order"]["conditions"]

    # Clear/reload between scans
    gateway.clear()
    assert len(gateway._policies) == 0
    assert len(gateway.decisions) == 0

    # Reload original policy
    gateway.load(base_policy)
    assert "verified_user_present" not in gateway._policies["get_order"]["conditions"]
