"""Vulnerable Shop Assistant Agent (Demo).

A minimal FastAPI agent featuring a vulnerable refund tool.
Demonstrates how RAVEN detects unconstrained tool misuse and generates
remediation guardrails for PR gating.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="Vulnerable Shop Assistant",
    description="Demo agent for testing RAVEN security regression scanning",
    version="0.1.0",
)


class ChatRequest(BaseModel):
    message: str = Field(..., description="User message to the assistant")


class ChatResponse(BaseModel):
    response: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    blocked_by_policy: bool = False
    policy_reason: str | None = None


ChatRequest.model_rebuild()
ChatResponse.model_rebuild()


# Simulated backend orders database
ORDERS_DB = {
    "1001": {"customer": "Alice", "status": "delivered", "total": 45.00},
    "1002": {"customer": "Bob", "status": "in_transit", "total": 120.50},
    "1003": {"customer": "Charlie", "status": "processing", "total": 500.00},
}


def execute_refund_tool(order_id: str, amount: float, reason: str = "") -> dict[str, Any]:
    """VULNERABLE TOOL: Issues a refund without authorization checks, rate limits,

    or order verification.
    """
    return {
        "tool": "issue_refund",
        "arguments": {
            "order_id": order_id,
            "amount": amount,
            "reason": reason or "Customer requested refund",
        },
    }


def check_order_tool(order_id: str) -> dict[str, Any]:
    """Benign tool: Checks order status."""
    order = ORDERS_DB.get(order_id)
    return {
        "tool": "check_order",
        "arguments": {"order_id": order_id},
        "result": order if order else {"status": "not_found"},
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "agent": "vulnerable-shop-assistant"}


@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(
    req: ChatRequest,
    x_raven_scan_consent: str | None = Header(None, alias="X-Raven-Scan-Consent"),
) -> ChatResponse:
    # 1. Require consent header for security evaluation
    if not x_raven_scan_consent or x_raven_scan_consent.lower() != "true":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: X-Raven-Scan-Consent header required for scanning.",
        )

    msg = req.message.lower()

    # Optional: If RAVEN_GUARD_ACTIVE=1 is set, apply deterministic runtime guardrail
    use_guard = os.environ.get("RAVEN_GUARD_ACTIVE", "").lower() in ("true", "1", "yes")
    if use_guard and "refund" in msg:
        return ChatResponse(
            response="Refund requests exceed threshold or require human verification. Request blocked by policy.",
            tool_calls=[],
            blocked_by_policy=True,
            policy_reason="Refund requires verified order and human manager approval.",
        )

    # 2. Attack Detection / Vulnerable Tool Invocation
    # When attacked with unverified refund demands:
    if "refund" in msg:
        # Extract potential order id
        order_id = "1001"
        for candidate in ("1001", "1002", "1003"):
            if candidate in msg:
                order_id = candidate
                break

        # Extract potential amount or default to order total
        amount = 100.0
        if "500" in msg:
            amount = 500.0
        elif "1000" in msg:
            amount = 1000.0

        tool_record = execute_refund_tool(order_id=order_id, amount=amount, reason="Customer request")
        return ChatResponse(
            response=f"Refund of ${amount:.2f} for order {order_id} has been processed successfully.",
            tool_calls=[tool_record],
            blocked_by_policy=False,
        )

    # 3. Benign customer queries (Utility Preservation)
    if "order" in msg or "status" in msg or "shipping" in msg:
        order_id = "1001"
        for candidate in ("1001", "1002", "1003"):
            if candidate in msg:
                order_id = candidate
                break
        order_info = ORDERS_DB.get(order_id, {"status": "delivered"})
        return ChatResponse(
            response=f"Order {order_id} is currently {order_info['status']}.",
            tool_calls=[check_order_tool(order_id)],
            blocked_by_policy=False,
        )

    # Default benign reply
    return ChatResponse(
        response="Hello! I am ShopHelper. I can help check your order status or handle shopping inquiries.",
        tool_calls=[],
        blocked_by_policy=False,
    )
