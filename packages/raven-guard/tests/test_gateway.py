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


def test_gateway_reload_when_file_updated(tmp_path):
    pfile = tmp_path / "raven-policy.yaml"
    pfile.write_text("""
version: "v1"
tools:
  - tool: tool_a
    conditions: []
""")

    gw = PolicyGateway(pfile)
    assert "tool_a" in gw.tools
    assert "tool_b" not in gw.tools

    # Calling reload without modifications returns False
    assert gw.reload() is False

    # Overwrite file with tool_b added
    import time
    time.sleep(0.01)
    pfile.write_text("""
version: "v2"
tools:
  - tool: tool_a
    conditions: []
  - tool: tool_b
    conditions: []
""")

    reloaded = gw.reload()
    assert reloaded is True
    assert gw.version == "v2"
    assert "tool_b" in gw.tools


def test_gateway_reload_force_and_no_file():
    # In-memory dictionary has no policy path
    gw = PolicyGateway({"version": "v1", "tools": []})
    assert gw.reload() is False
    assert gw.reload(force=True) is False


def test_gateway_auto_reload(tmp_path):
    pfile = tmp_path / "raven-policy.yaml"
    pfile.write_text("""
version: "v1"
tools:
  - tool: initial_tool
""")

    gw = PolicyGateway(pfile)
    assert "initial_tool" in gw.tools

    gw.start_auto_reload(interval_seconds=0.05)

    import time
    time.sleep(0.02)
    pfile.write_text("""
version: "v2"
tools:
  - tool: updated_tool
""")

    # Wait for background thread to detect mtime change
    deadline = time.time() + 1.0
    while time.time() < deadline and "updated_tool" not in gw.tools:
        time.sleep(0.05)

    gw.stop_auto_reload()
    assert "updated_tool" in gw.tools
    assert gw._reloader is None


def test_gateway_from_yaml_and_from_file(tmp_path):
    pfile = tmp_path / "custom-policy.yaml"
    pfile.write_text("""
version: "v1"
tools:
  - tool: test_service
    conditions: []
""")

    gw_yaml = PolicyGateway.from_yaml(pfile)
    assert gw_yaml.version == "v1"
    assert "test_service" in gw_yaml.tools

    gw_file = PolicyGateway.from_file(pfile)
    assert gw_file.version == "v1"
    assert "test_service" in gw_file.tools

    # Direct YAML string
    gw_str = PolicyGateway.from_yaml("version: v3\ntools:\n  - tool: inline_tool")
    assert gw_str.version == "v3"
    assert "inline_tool" in gw_str.tools


