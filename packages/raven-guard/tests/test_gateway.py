"""Unit tests for PolicyGateway core authorization and fail-closed logic."""

from __future__ import annotations

import pytest

from raven_guard import (
    PolicyGateway,
    SecurityContext,
    ToolPolicy,
)


@pytest.fixture
def sample_policy():
    return {
        "version": "v1",
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


def test_gateway_initialization(sample_policy):
    gw = PolicyGateway(sample_policy)
    assert gw.version == "v1"
    assert gw.fail_closed is True
    assert "issue_refund" in gw.tools
    assert "get_order" in gw.tools


def test_gateway_fail_closed_on_unknown_tool(sample_policy):
    gw = PolicyGateway(sample_policy)
    decision = gw.authorize("drop_database", {"table": "users"})
    assert not decision
    assert decision.allowed is False
    assert "no_policy_for_tool:drop_database" in decision.reason
    assert decision.violations == ["no_policy_for_tool:drop_database"]


def test_gateway_permissive_mode_when_configured():
    gw = PolicyGateway({"tools": [], "fail_closed": False}, fail_closed=False)
    decision = gw.authorize("unregistered_tool", {"action": "read"})
    assert decision.allowed is True
    assert decision.reason == "allowed_permissive_no_policy"


def test_gateway_malformed_arguments_handling(sample_policy):
    gw = PolicyGateway(sample_policy)

    # Arguments not a dict
    dec_not_dict = gw.authorize("issue_refund", "not_a_dict")  # type: ignore
    assert not dec_not_dict
    assert dec_not_dict.reason == "malformed_arguments:not_a_dict"

    # Negative amount
    dec_neg = gw.authorize("issue_refund", {"order_id": "ORD-1", "amount": -10.0})
    assert not dec_neg
    assert dec_neg.reason == "malformed_arguments:negative_amount"

    # Non-numeric string amount
    dec_invalid_amt = gw.authorize("issue_refund", {"order_id": "ORD-1", "amount": "free"})
    assert not dec_invalid_amt
    assert dec_invalid_amt.reason == "malformed_arguments:invalid_amount_type"


def test_gateway_apply_candidate(sample_policy):
    gw = PolicyGateway(sample_policy)

    # Initially transfer_funds has no policy
    assert not gw.authorize("transfer_funds", {"to": "attacker"})

    # Apply candidate dynamically (compiled by RAVEN hardening)
    gw.apply_candidate({
        "tool": "transfer_funds",
        "conditions": ["verified_user_present"],
        "high_value_action": "human_approval_required",
        "amount_threshold": 50.0,
    })

    # Unauthorized without verified user
    ctx = SecurityContext(verified_user=False)
    assert not gw.authorize("transfer_funds", {"amount": 20.0}, ctx)

    # Authorized with verified user
    ctx_ok = SecurityContext(verified_user=True)
    assert gw.authorize("transfer_funds", {"amount": 20.0}, ctx_ok)


def test_gateway_apply_candidate_as_tool_policy():
    gw = PolicyGateway({"tools": []})
    tp = ToolPolicy(tool="query_data", conditions=[])
    gw.apply_candidate(tp)
    assert gw.authorize("query_data", {})


def test_gateway_apply_candidate_invalid_format():
    gw = PolicyGateway({"tools": []})
    with pytest.raises(ValueError):
        gw.apply_candidate("not_a_candidate")  # type: ignore


def test_gateway_clear(sample_policy):
    gw = PolicyGateway(sample_policy)
    assert len(gw.tools) == 2
    gw.authorize("get_order", {"order_id": "ORD-1"})
    assert len(gw.decisions) == 1

    gw.clear()
    assert len(gw.tools) == 0
    assert len(gw.decisions) == 0


def test_gateway_audit_log_rotation(sample_policy):
    gw = PolicyGateway(sample_policy, audit_log_size=3)
    for i in range(5):
        gw.authorize("get_order", {"order_id": f"ORD-{i}"})

    assert len(gw.decisions) == 3
    # Check that oldest were evicted and newest retained
    orders = [d["arguments"]["order_id"] for d in gw.decisions]
    assert orders == ["ORD-2", "ORD-3", "ORD-4"]
