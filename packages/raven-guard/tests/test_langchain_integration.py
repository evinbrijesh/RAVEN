"""Integration tests for LangGraph ToolNode and LangChain tool interceptor."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from raven_guard import (
    ApprovalRequiredError,
    PolicyGateway,
    PolicyViolationError,
    security_context,
)
from raven_guard.integrations import (
    RavenGuardCallbackHandler,
    RavenGuardToolNode,
    RavenToolInterceptor,
    wrap_tool,
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
                "tool": "lookup_inventory",
                "conditions": [],
            },
            {
                "tool": "async_lookup",
                "conditions": [],
            },
            {
                "tool": "get_customer_records",
                "conditions": [
                    "claims_match:customer_id==user_id",
                ],
            },
        ],
    })


@tool
def issue_refund(order_id: str, amount: float) -> str:
    """Refund a customer order."""
    return f"Successfully refunded ${amount} for order {order_id}"


@tool
def lookup_inventory(sku: str) -> str:
    """Check inventory for a product SKU."""
    return f"Inventory for {sku}: 42 in stock"


@tool
async def async_lookup(sku: str) -> str:
    """Asynchronously check inventory."""
    return f"Async inventory for {sku}: 100 in stock"


# ─────────────────────────────────────────────────────────────────────────────
# 1. RavenGuardToolNode Standalone & Config Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_tool_node_allowed_invocation(gateway):
    node = RavenGuardToolNode([lookup_inventory], gateway=gateway)
    ai_msg = AIMessage(
        content="",
        tool_calls=[{
            "name": "lookup_inventory",
            "args": {"sku": "SKU-99"},
            "id": "call_1",
            "type": "tool_call",
        }],
    )

    result = node.invoke({"messages": [ai_msg]})
    assert len(result["messages"]) == 1
    tool_msg = result["messages"][0]
    assert isinstance(tool_msg, ToolMessage)
    assert tool_msg.tool_call_id == "call_1"
    assert "42 in stock" in tool_msg.content


def test_tool_node_blocks_unauthorized_call_raise_mode(gateway):
    node = RavenGuardToolNode([issue_refund], gateway=gateway, on_violation="raise")
    ai_msg = AIMessage(
        content="",
        tool_calls=[{
            "name": "issue_refund",
            "args": {"order_id": "ORD-1", "amount": 25.0},
            "id": "call_unverified",
            "type": "tool_call",
        }],
    )

    # Missing verified_order_id and verified_user
    with pytest.raises(PolicyViolationError) as exc_info:
        node.invoke({"messages": [ai_msg]})

    assert exc_info.value.tool == "issue_refund"
    assert exc_info.value.reason == "missing_verified_order_id"


def test_tool_node_blocks_high_value_escalation(gateway):
    node = RavenGuardToolNode([issue_refund], gateway=gateway, on_violation="raise")
    ai_msg = AIMessage(
        content="",
        tool_calls=[{
            "name": "issue_refund",
            "args": {"order_id": "ORD-1", "amount": 500.0},
            "id": "call_high_val",
            "type": "tool_call",
        }],
    )

    # Context verified, but amount exceeds $100.0 threshold
    with security_context(verified_user=True, verified_order_id=True):
        with pytest.raises(ApprovalRequiredError) as exc_info:
            node.invoke({"messages": [ai_msg]})

        assert exc_info.value.tool == "issue_refund"
        assert exc_info.value.reason == "high_value_action:approval_required"


def test_tool_node_return_message_mode(gateway):
    node = RavenGuardToolNode([issue_refund], gateway=gateway, on_violation="return_message")
    ai_msg = AIMessage(
        content="",
        tool_calls=[{
            "name": "issue_refund",
            "args": {"order_id": "ORD-1", "amount": 25.0},
            "id": "call_blocked",
            "type": "tool_call",
        }],
    )

    # Should not raise; returns ToolMessage with status="error"
    result = node.invoke({"messages": [ai_msg]})
    assert len(result["messages"]) == 1
    tool_msg = result["messages"][0]
    assert isinstance(tool_msg, ToolMessage)
    assert tool_msg.status == "error"
    assert "blocked by security policy" in tool_msg.content.lower()
    assert "missing_verified_order_id" in tool_msg.content


def test_tool_node_context_from_config(gateway):
    node = RavenGuardToolNode([issue_refund], gateway=gateway)
    ai_msg = AIMessage(
        content="",
        tool_calls=[{
            "name": "issue_refund",
            "args": {"order_id": "ORD-1", "amount": 25.0},
            "id": "call_cfg",
            "type": "tool_call",
        }],
    )

    config = {
        "configurable": {
            "security_context": {
                "verified_user": True,
                "verified_order_id": True,
            }
        }
    }

    result = node.invoke({"messages": [ai_msg]}, config=config)
    assert "Successfully refunded" in result["messages"][0].content


@pytest.mark.asyncio
async def test_async_tool_node_execution(gateway):
    node = RavenGuardToolNode([async_lookup], gateway=gateway)
    ai_msg = AIMessage(
        content="",
        tool_calls=[{
            "name": "async_lookup",
            "args": {"sku": "ASYNC-SKU"},
            "id": "call_async",
            "type": "tool_call",
        }],
    )

    result = await node.ainvoke({"messages": [ai_msg]})
    assert "Async inventory for ASYNC-SKU: 100 in stock" in result["messages"][0].content


# ─────────────────────────────────────────────────────────────────────────────
# 2. End-to-End LangGraph StateGraph Integration
# ─────────────────────────────────────────────────────────────────────────────

def test_langgraph_stategraph_integration(gateway):
    builder = StateGraph(MessagesState)
    tool_node = RavenGuardToolNode(
        [issue_refund, lookup_inventory],
        gateway=gateway,
        on_violation="return_message",
    )

    builder.add_node("tools", tool_node)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    graph = builder.compile()

    # Step 1: LLM attempts prompt injection to steal Bob's refund ($500)
    injected_call = AIMessage(
        content="",
        tool_calls=[{
            "name": "issue_refund",
            "args": {"order_id": "BOB-99", "amount": 500.0},
            "id": "attack_call",
            "type": "tool_call",
        }],
    )

    # Execute graph under Alice's unverified context
    output = graph.invoke({"messages": [injected_call]})
    last_response = output["messages"][-1]

    # Verify that the tool was NOT executed and security error was returned
    assert isinstance(last_response, ToolMessage)
    assert last_response.status == "error"
    assert "blocked by security policy" in last_response.content.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 3. RavenGuardCallbackHandler & RavenToolInterceptor Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_callback_handler_interception(gateway):
    handler = RavenGuardCallbackHandler(gateway=gateway)

    # 1. Allowed tool invocation check
    handler.on_tool_start(
        serialized={"name": "lookup_inventory"},
        input_str="",
        inputs={"sku": "SKU-1"},
        run_id="00000000-0000-0000-0000-000000000001",
    )

    # 2. Blocked tool invocation check
    with pytest.raises(PolicyViolationError) as exc_info:
        handler.on_tool_start(
            serialized={"name": "issue_refund"},
            input_str="",
            inputs={"order_id": "ORD-1", "amount": 50.0},
            run_id="00000000-0000-0000-0000-000000000002",
        )

    assert exc_info.value.tool == "issue_refund"
    assert exc_info.value.reason == "missing_verified_order_id"


def test_interceptor_alias_equivalence(gateway):
    assert RavenToolInterceptor is RavenGuardCallbackHandler
    interceptor = RavenToolInterceptor(gateway=gateway)
    assert isinstance(interceptor, RavenGuardCallbackHandler)


# ─────────────────────────────────────────────────────────────────────────────
# 4. wrap_tool Helper Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_wrap_tool_enforces_policy(gateway):
    guarded_lookup = wrap_tool(lookup_inventory, gateway=gateway)
    res = guarded_lookup.invoke({"sku": "SKU-WRAPPED"})
    assert "42 in stock" in res

    guarded_refund = wrap_tool(issue_refund, gateway=gateway)
    with pytest.raises(PolicyViolationError):
        guarded_refund.invoke({"order_id": "ORD-1", "amount": 25.0})
