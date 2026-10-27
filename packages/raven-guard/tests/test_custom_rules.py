"""Unit tests for custom conditions and decision serialization."""

from __future__ import annotations

from raven_guard import Decision, PolicyGateway, SecurityContext, ToolPolicy


def test_custom_condition_registration():
    gw = PolicyGateway({
        "tools": [
            {
                "tool": "export_records",
                "conditions": ["ip_allowlist_check"],
            }
        ]
    })

    def ip_validator(args: dict, ctx: SecurityContext, policy: ToolPolicy) -> tuple[bool, str]:
        client_ip = args.get("client_ip")
        if client_ip == "10.0.0.1":
            return True, "ok"
        return False, "ip_not_in_internal_allowlist"

    gw.register_condition("ip_allowlist_check", ip_validator)

    # Allowed IP
    res_ok = gw.authorize("export_records", {"client_ip": "10.0.0.1"})
    assert res_ok.allowed is True

    # Blocked IP
    res_deny = gw.authorize("export_records", {"client_ip": "198.51.100.2"})
    assert res_deny.allowed is False
    assert res_deny.reason == "ip_not_in_internal_allowlist"


def test_custom_condition_exception_fails_closed():
    gw = PolicyGateway({
        "tools": [
            {
                "tool": "flaky_tool",
                "conditions": ["buggy_condition"],
            }
        ]
    })

    def buggy_validator(args: dict, ctx: SecurityContext, policy: ToolPolicy) -> tuple[bool, str]:
        raise RuntimeError("database unreachable")

    gw.register_condition("buggy_condition", buggy_validator)

    # Should fail closed and not crash the process
    res = gw.authorize("flaky_tool", {})
    assert res.allowed is False
    assert "custom_condition_error:buggy_condition" in res.reason


def test_decision_methods_and_serialization():
    dec = Decision(
        allowed=True,
        reason="all_conditions_met",
        tool="test_tool",
        policy_source="candidate",
        violations=[],
        metadata={"key": "val"},
    )
    assert bool(dec) is True
    d = dec.to_dict()
    assert d["allowed"] is True
    assert d["tool"] == "test_tool"
    assert d["metadata"] == {"key": "val"}

    dec_false = Decision(allowed=False, reason="denied")
    assert bool(dec_false) is False
