"""Unit tests for @gateway.protect function decorators (sync and async)."""

from __future__ import annotations

import pytest
from raven_guard import (
    ApprovalRequiredError,
    MalformedArgumentsError,
    PolicyGateway,
    PolicyViolationError,
    SecurityContext,
    security_context,
)


@pytest.fixture
def gateway():
    return PolicyGateway({
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
            },
            {
                "tool": "read_user_profile",
                "conditions": ["verified_user_present"],
            },
        ],
    })


def test_sync_decorator_success(gateway):
    @gateway.protect(tool="issue_refund")
    def refund(order_id: str, amount: float):
        return {"status": "ok", "refunded": amount}

    with security_context(verified_user=True, verified_order_id=True):
        res = refund("ORD-101", 25.0)
        assert res["status"] == "ok"
        assert res["refunded"] == 25.0


def test_sync_decorator_violation_raises(gateway):
    @gateway.protect(tool="issue_refund")
    def refund(order_id: str, amount: float):
        return {"status": "ok"}

    # Missing verified_order context
    with pytest.raises(PolicyViolationError) as exc_info:
        refund("ORD-101", 25.0)
    assert exc_info.value.tool == "issue_refund"
    assert exc_info.value.reason == "missing_verified_order_id"

    # Missing verified_user context
    with security_context(verified_order_id=True):
        with pytest.raises(PolicyViolationError) as exc_info2:
            refund("ORD-101", 25.0)
        assert exc_info2.value.reason == "missing_verified_user"


def test_sync_decorator_approval_required(gateway):
    @gateway.protect(tool="issue_refund")
    def refund(order_id: str, amount: float):
        return {"status": "ok"}

    # Amount $500 >= threshold $100
    with security_context(verified_user=True, verified_order_id=True):
        with pytest.raises(ApprovalRequiredError) as exc_info:
            refund("ORD-101", 500.0)

        assert exc_info.value.tool == "issue_refund"
        assert exc_info.value.reason == "high_value_action:approval_required"


def test_sync_decorator_malformed_arguments(gateway):
    @gateway.protect(tool="issue_refund")
    def refund(order_id: str, amount: float):
        return {"status": "ok"}

    with security_context(verified_user=True, verified_order_id=True):
        with pytest.raises(MalformedArgumentsError) as exc_info:
            refund("ORD-101", -50.0)

        assert exc_info.value.reason == "malformed_arguments:negative_amount"


@pytest.mark.asyncio
async def test_async_decorator_success(gateway):
    @gateway.protect(tool="issue_refund")
    async def async_refund(order_id: str, amount: float):
        return {"async": True, "amount": amount}

    with security_context(verified_user=True, verified_order_id=True):
        res = await async_refund("ORD-999", 15.0)
        assert res["async"] is True
        assert res["amount"] == 15.0


@pytest.mark.asyncio
async def test_async_decorator_violation_raises(gateway):
    @gateway.protect(tool="issue_refund")
    async def async_refund(order_id: str, amount: float):
        return {"async": True}

    with pytest.raises(PolicyViolationError) as exc_info:
        await async_refund("ORD-999", 15.0)

    assert exc_info.value.reason == "missing_verified_order_id"


def test_decorator_default_tool_name_inference(gateway):
    @gateway.protect()
    def read_user_profile(user_id: str):
        return {"user": user_id}

    with security_context(verified_user=True):
        res = read_user_profile("user_123")
        assert res["user"] == "user_123"


def test_decorator_explicit_context_kwarg(gateway):
    @gateway.protect(tool="read_user_profile")
    def get_profile(user_id: str, _context=None):
        return {"user": user_id}

    # Pass context directly as parameter
    res = get_profile("user_123", _context=SecurityContext(verified_user=True))
    assert res["user"] == "user_123"

    # Pass dict context directly as parameter
    res2 = get_profile("user_123", _context={"verified_user": True})
    assert res2["user"] == "user_123"


def test_decorator_on_violation_return_decision(gateway):
    @gateway.protect(tool="issue_refund", on_violation="return_decision")
    def refund(order_id: str, amount: float):
        return {"status": "ok"}

    # Should not raise; returns Decision
    decision = refund("ORD-101", 25.0)
    assert not decision.allowed
    assert decision.reason == "missing_verified_order_id"


def test_decorator_on_violation_callback(gateway):
    def custom_handler(decision, call_args):
        return {"blocked": True, "reason": decision.reason, "args": call_args}

    @gateway.protect(tool="issue_refund", on_violation=custom_handler)
    def refund(order_id: str, amount: float):
        return {"status": "ok"}

    res = refund("ORD-101", 25.0)
    assert res["blocked"] is True
    assert res["reason"] == "missing_verified_order_id"
    assert res["args"]["order_id"] == "ORD-101"


def test_decorator_preserves_metadata(gateway):
    @gateway.protect(tool="read_user_profile")
    def sample_tool(user_id: str) -> str:
        """Sample docstring for tool."""
        return user_id

    assert sample_tool.__name__ == "sample_tool"
    assert sample_tool.__doc__ == "Sample docstring for tool."
