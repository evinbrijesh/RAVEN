"""OpenTelemetry security observability and tracing listener for raven-guard."""

from __future__ import annotations

import json
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from raven_guard.gateway import PolicyGateway
from raven_guard.telemetry import register_telemetry_listener

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, StatusCode, Tracer
    HAS_OPENTELEMETRY = True
except ImportError:
    HAS_OPENTELEMETRY = False
    trace = None  # type: ignore
    Span = Any  # type: ignore
    Tracer = Any  # type: ignore

    class StatusCode:  # type: ignore
        OK = 1
        ERROR = 2


class OpenTelemetrySecurityListener:
    """Listener that enriches active OpenTelemetry spans with security policy attributes."""

    def __init__(
        self,
        set_error_status_on_violation: bool = True,
        record_span_events: bool = True,
        attribute_prefix: str = "security.",
    ) -> None:
        self.set_error_status_on_violation = set_error_status_on_violation
        self.record_span_events = record_span_events
        self.prefix = attribute_prefix

    def __call__(self, event: dict[str, Any]) -> None:
        """Invoked when PolicyGateway emits a security audit event."""
        if not HAS_OPENTELEMETRY or trace is None:
            return

        span = trace.get_current_span()
        if span is None or not hasattr(span, "is_recording") or not span.is_recording():
            return

        tool = event.get("tool", "")
        allowed = event.get("allowed", False)
        reason = event.get("reason", "")
        policy_source = event.get("policy_source", "gateway_default")
        violations = event.get("violations", [])
        user_id = event.get("user_id")
        session_id = event.get("session_id")
        event_type = event.get("event_type", "tool_call_evaluated")

        # Set standardized GenAI/Security semantic attributes
        span.set_attribute(f"{self.prefix}policy.tool", tool)
        span.set_attribute(f"{self.prefix}policy.allowed", allowed)
        span.set_attribute(f"{self.prefix}policy.reason", reason)
        span.set_attribute(f"{self.prefix}policy.source", policy_source)
        if user_id:
            span.set_attribute(f"{self.prefix}user.id", user_id)
        if session_id:
            span.set_attribute(f"{self.prefix}session.id", session_id)
        if violations:
            span.set_attribute(f"{self.prefix}policy.violations", json.dumps(violations))

        # Handle violations & high-value escalations
        if not allowed:
            span.set_attribute(f"{self.prefix}violation.type", event_type)
            span.set_attribute(f"{self.prefix}violation.reason", reason)

            if self.set_error_status_on_violation and hasattr(span, "set_status"):
                span.set_status(StatusCode.ERROR, f"Policy violation on '{tool}': {reason}")

            if self.record_span_events and hasattr(span, "add_event"):
                event_name = (
                    "security.policy.escalation"
                    if reason == "high_value_action:approval_required"
                    else "security.policy.violation"
                )
                span.add_event(
                    event_name,
                    attributes={
                        "tool": tool,
                        "reason": reason,
                        "violations": json.dumps(violations),
                        "user_id": user_id or "",
                    },
                )


def setup_opentelemetry(
    gateway: PolicyGateway,
    set_error_status_on_violation: bool = True,
    record_span_events: bool = True,
) -> OpenTelemetrySecurityListener:
    """Convenience helper to attach OpenTelemetry security telemetry to a PolicyGateway."""
    listener = OpenTelemetrySecurityListener(
        set_error_status_on_violation=set_error_status_on_violation,
        record_span_events=record_span_events,
    )
    register_telemetry_listener(listener)
    return listener


@contextmanager
def trace_tool_execution(
    tool: str,
    tracer: Tracer | None = None,
    attributes: dict[str, Any] | None = None,
) -> Generator[Span, None, None]:
    """Context manager creating a dedicated OpenTelemetry span for a tool execution."""
    if not HAS_OPENTELEMETRY or trace is None:
        yield None  # type: ignore
        return

    active_tracer = tracer or trace.get_tracer("raven_guard")
    span_name = f"tool.call.{tool}"
    with active_tracer.start_as_current_span(span_name) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        yield span
