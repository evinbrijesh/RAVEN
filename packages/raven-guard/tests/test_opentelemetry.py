"""Tests for OpenTelemetry security observability integration."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from opentelemetry.trace import StatusCode

from raven_guard import PolicyGateway, SecurityContext
from raven_guard.integrations.opentelemetry import (
    OpenTelemetrySecurityListener,
    setup_opentelemetry,
    trace_tool_execution,
)


def _make_mock_span(recording: bool = True) -> MagicMock:
    span = MagicMock()
    span.is_recording.return_value = recording
    return span


def test_listener_sets_attributes_on_allowed_span():
    mock_span = _make_mock_span(recording=True)
    listener = OpenTelemetrySecurityListener()

    event = {
        "tool": "search_catalog",
        "allowed": True,
        "reason": "allowed",
        "policy_source": "yaml",
        "user_id": "user-42",
        "session_id": "sess-99",
        "violations": [],
    }

    with patch("raven_guard.integrations.opentelemetry.trace.get_current_span", return_value=mock_span):
        listener(event)

    mock_span.set_attribute.assert_any_call("security.policy.tool", "search_catalog")
    mock_span.set_attribute.assert_any_call("security.policy.allowed", True)
    mock_span.set_attribute.assert_any_call("security.policy.reason", "allowed")
    mock_span.set_attribute.assert_any_call("security.policy.source", "yaml")
    mock_span.set_attribute.assert_any_call("security.user.id", "user-42")
    mock_span.set_attribute.assert_any_call("security.session.id", "sess-99")
    mock_span.set_status.assert_not_called()
    mock_span.add_event.assert_not_called()


def test_listener_sets_error_and_event_on_violation():
    mock_span = _make_mock_span(recording=True)
    listener = OpenTelemetrySecurityListener()

    event = {
        "tool": "issue_refund",
        "allowed": False,
        "reason": "amount_exceeds_max:100.0",
        "violations": ["amount:100.0"],
        "user_id": "user-attacker",
        "event_type": "tool_call_evaluated",
    }

    with patch("raven_guard.integrations.opentelemetry.trace.get_current_span", return_value=mock_span):
        listener(event)

    mock_span.set_attribute.assert_any_call("security.policy.tool", "issue_refund")
    mock_span.set_attribute.assert_any_call("security.policy.allowed", False)
    mock_span.set_attribute.assert_any_call("security.violation.reason", "amount_exceeds_max:100.0")
    mock_span.set_attribute.assert_any_call("security.policy.violations", json.dumps(["amount:100.0"]))
    mock_span.set_status.assert_called_once_with(
        StatusCode.ERROR, "Policy violation on 'issue_refund': amount_exceeds_max:100.0"
    )
    mock_span.add_event.assert_called_once_with(
        "security.policy.violation",
        attributes={
            "tool": "issue_refund",
            "reason": "amount_exceeds_max:100.0",
            "violations": json.dumps(["amount:100.0"]),
            "user_id": "user-attacker",
        },
    )


def test_listener_records_escalation_event_for_approval_required():
    mock_span = _make_mock_span(recording=True)
    listener = OpenTelemetrySecurityListener()

    event = {
        "tool": "delete_database",
        "allowed": False,
        "reason": "high_value_action:approval_required",
        "violations": [],
        "user_id": "user-admin",
    }

    with patch("raven_guard.integrations.opentelemetry.trace.get_current_span", return_value=mock_span):
        listener(event)

    mock_span.add_event.assert_called_once_with(
        "security.policy.escalation",
        attributes={
            "tool": "delete_database",
            "reason": "high_value_action:approval_required",
            "violations": "[]",
            "user_id": "user-admin",
        },
    )


def test_listener_skips_when_span_not_recording():
    mock_span = _make_mock_span(recording=False)
    listener = OpenTelemetrySecurityListener()

    event = {"tool": "test", "allowed": True}

    with patch("raven_guard.integrations.opentelemetry.trace.get_current_span", return_value=mock_span):
        listener(event)

    mock_span.set_attribute.assert_not_called()
    mock_span.set_status.assert_not_called()
    mock_span.add_event.assert_not_called()


def test_listener_respects_custom_prefix_and_disabled_flags():
    mock_span = _make_mock_span(recording=True)
    listener = OpenTelemetrySecurityListener(
        attribute_prefix="genai.",
        set_error_status_on_violation=False,
        record_span_events=False,
    )

    event = {
        "tool": "export_logs",
        "allowed": False,
        "reason": "policy_denied",
        "violations": [],
    }

    with patch("raven_guard.integrations.opentelemetry.trace.get_current_span", return_value=mock_span):
        listener(event)

    mock_span.set_attribute.assert_any_call("genai.policy.tool", "export_logs")
    mock_span.set_attribute.assert_any_call("genai.policy.allowed", False)
    mock_span.set_status.assert_not_called()
    mock_span.add_event.assert_not_called()


def test_setup_opentelemetry_e2e_with_gateway(tmp_path):
    policy_content = """
policy_version: "2026-03-01"
enforcement_mode: "strict"
tools:
  read_order:
    description: "Read order details"
    allowed: true
"""
    pfile = tmp_path / "test-policy.yaml"
    pfile.write_text(policy_content)

    mock_span = _make_mock_span(recording=True)
    gateway = PolicyGateway(policy=pfile)
    setup_opentelemetry(gateway)

    with patch("raven_guard.integrations.opentelemetry.trace.get_current_span", return_value=mock_span):
        decision = gateway.authorize(
            "read_order",
            {"order_id": "ORD-123"},
            context=SecurityContext(user_id="alice"),
        )
        assert decision.allowed is True

    mock_span.set_attribute.assert_any_call("security.policy.tool", "read_order")
    mock_span.set_attribute.assert_any_call("security.policy.allowed", True)
    mock_span.set_attribute.assert_any_call("security.user.id", "alice")


def test_trace_tool_execution_context_manager():
    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with trace_tool_execution("query_db", tracer=mock_tracer, attributes={"env": "prod"}) as span:
        assert span is mock_span

    mock_tracer.start_as_current_span.assert_called_once_with("tool.call.query_db")
    mock_span.set_attribute.assert_called_once_with("env", "prod")
