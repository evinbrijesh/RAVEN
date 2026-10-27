"""Unit tests for condition checks, parameter bounds, and role constraints."""

from __future__ import annotations

import pytest
from raven_guard import PolicyGateway, SecurityContext


@pytest.fixture
def complex_policy():
    return {
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
                "parameter_rules": {
                    "account_number": {
                        "required": True,
                        "regex": r"^ACC-\d{4}$",
                    },
                    "memo": {
                        "regex": r"^[a-zA-Z0-9\s]+$",
                    },
                },
                "allowed_roles": ["finance_admin", "billing_manager"],
            },
            {
                "tool": "modify_order",
                "conditions": [
                    "verified_order_id_present",
                    "user_id_matches_context",
                ],
                "parameter_rules": {
                    "quantity": {
                        "min": 1,
                        "max": 10,
                    },
                    "action": {
                        "in": ["add", "remove", "update"],
                    },
                },
            },
            {
                "tool": "unknown_cond_tool",
                "conditions": ["nonexistent_condition_flag"],
            },
        ],
    }


def test_amount_below_threshold_boundaries():
    gw = PolicyGateway({
        "tools": [
            {
                "tool": "charge",
                "conditions": ["amount_below_threshold"],
                "amount_threshold": 50.0,
            }
        ]
    })

    # Under threshold
    assert gw.authorize("charge", {"amount": 49.99}).allowed is True

    # At threshold (threshold is strictly exclusive in fail-closed: >= threshold denies)
    dec_at = gw.authorize("charge", {"amount": 50.0})
    assert dec_at.allowed is False
    assert dec_at.reason == "amount_at_or_above_threshold"

    # Above threshold
    dec_above = gw.authorize("charge", {"amount": 100.0})
    assert dec_above.allowed is False
    assert dec_above.reason == "amount_at_or_above_threshold"

    # Missing amount when condition is enforced
    dec_missing = gw.authorize("charge", {})
    assert dec_missing.allowed is False
    assert dec_missing.reason == "missing_amount_for_threshold_check"


def test_user_id_matches_context():
    gw = PolicyGateway({
        "tools": [
            {
                "tool": "view_records",
                "conditions": ["user_id_matches_context"],
            }
        ]
    })

    ctx = SecurityContext(user_id="user_alice")

    # Matching user_id
    assert gw.authorize("view_records", {"user_id": "user_alice"}, ctx).allowed is True

    # Impersonation attempt / mismatched user_id
    dec_mismatch = gw.authorize("view_records", {"user_id": "user_bob"}, ctx)
    assert dec_mismatch.allowed is False
    assert dec_mismatch.reason == "user_id_mismatch"


def test_unknown_condition_fails_closed(complex_policy):
    gw = PolicyGateway(complex_policy)
    dec = gw.authorize("unknown_cond_tool", {})
    assert dec.allowed is False
    assert "unknown_condition:nonexistent_condition_flag" in dec.reason


def test_role_based_privilege_check(complex_policy):
    gw = PolicyGateway(complex_policy)

    # Valid role
    ctx_admin = SecurityContext(
        verified_user=True,
        roles=["support_agent", "finance_admin"],
        amount=10.0,
    )
    dec_admin = gw.authorize(
        "transfer_funds",
        {"amount": 10.0, "account_number": "ACC-1234"},
        ctx_admin,
    )
    assert dec_admin.allowed is True

    # Invalid role
    ctx_guest = SecurityContext(
        verified_user=True,
        roles=["support_agent"],
        amount=10.0,
    )
    dec_guest = gw.authorize(
        "transfer_funds",
        {"amount": 10.0, "account_number": "ACC-1234"},
        ctx_guest,
    )
    assert dec_guest.allowed is False
    assert dec_guest.reason == "insufficient_role_privilege"


def test_parameter_bounds_and_regex(complex_policy):
    gw = PolicyGateway(complex_policy)
    ctx = SecurityContext(
        verified_order_id=True,
        order_id="ORD-99",
        user_id="alice",
    )

    # Valid parameters
    valid_dec = gw.authorize(
        "modify_order",
        {"order_id": "ORD-99", "user_id": "alice", "quantity": 5, "action": "add"},
        ctx,
    )
    assert valid_dec.allowed is True

    # Exceeds max quantity
    dec_max = gw.authorize(
        "modify_order",
        {"order_id": "ORD-99", "user_id": "alice", "quantity": 99, "action": "add"},
        ctx,
    )
    assert dec_max.allowed is False
    assert "parameter_rule_violation:quantity:exceeds_max_10" in dec_max.reason

    # Below min quantity
    dec_min = gw.authorize(
        "modify_order",
        {"order_id": "ORD-99", "user_id": "alice", "quantity": 0, "action": "add"},
        ctx,
    )
    assert dec_min.allowed is False
    assert "parameter_rule_violation:quantity:below_min_1" in dec_min.reason

    # Non-numeric quantity
    dec_non_num = gw.authorize(
        "modify_order",
        {"order_id": "ORD-99", "user_id": "alice", "quantity": "many", "action": "add"},
        ctx,
    )
    assert dec_non_num.allowed is False
    assert "parameter_rule_violation:quantity:not_numeric" in dec_non_num.reason

    # Invalid choice in 'in' constraint
    dec_choice = gw.authorize(
        "modify_order",
        {"order_id": "ORD-99", "user_id": "alice", "quantity": 2, "action": "delete_all"},
        ctx,
    )
    assert dec_choice.allowed is False
    assert "parameter_rule_violation:action:not_in_allowed_choices" in dec_choice.reason

    # Missing required parameter
    dec_missing_req = gw.authorize(
        "transfer_funds",
        {"amount": 10.0},  # missing account_number
        SecurityContext(verified_user=True, roles=["finance_admin"]),
    )
    assert dec_missing_req.allowed is False
    assert "parameter_rule_violation:account_number:required" in dec_missing_req.reason

    # Regex mismatch on account number
    dec_bad_regex = gw.authorize(
        "transfer_funds",
        {"amount": 10.0, "account_number": "INVALID-FORMAT"},
        SecurityContext(verified_user=True, roles=["finance_admin"]),
    )
    assert dec_bad_regex.allowed is False
    assert "parameter_rule_violation:account_number:regex_mismatch" in dec_bad_regex.reason


def test_high_value_action_from_context_amount(complex_policy):
    gw = PolicyGateway(complex_policy)
    # Amount is in context, not in arguments
    ctx = SecurityContext(
        verified_user=True,
        roles=["finance_admin"],
        amount=500.0,  # >= 100.0 threshold
    )
    dec = gw.authorize(
        "transfer_funds",
        {"account_number": "ACC-1234"},
        ctx,
    )
    assert dec.allowed is False
    assert dec.reason == "high_value_action:approval_required"


def test_security_context_from_arbitrary_object():
    class CustomContextObj:
        def __init__(self):
            self.verified_user = True
            self.verified_order_id = True
            self.order_id = "ORD-77"
            self.user_id = "u-77"
            self.amount = 45.0
            self.roles = ["auditor"]
            self.session_id = "sess-1"
            self.user_message = "hello"
            self.extra = {"tenant": "acme"}

    obj = CustomContextObj()
    ctx = SecurityContext.from_any(obj)
    assert ctx.verified_user is True
    assert ctx.order_id == "ORD-77"
    assert ctx.roles == ["auditor"]
    assert ctx.extra == {"tenant": "acme"}

    # from_any(None)
    assert SecurityContext.from_any(None).verified_user is False
