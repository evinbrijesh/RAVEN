"""Framework integrations for raven-guard."""

from raven_guard.integrations.fastapi import RavenGuardMiddleware
from raven_guard.integrations.langchain import (
    RavenGuardCallbackHandler,
    RavenGuardToolNode,
    RavenToolInterceptor,
    wrap_tool,
)
from raven_guard.integrations.opentelemetry import (
    OpenTelemetrySecurityListener,
    setup_opentelemetry,
    trace_tool_execution,
)

__all__ = [
    "OpenTelemetrySecurityListener",
    "RavenGuardCallbackHandler",
    "RavenGuardMiddleware",
    "RavenGuardToolNode",
    "RavenToolInterceptor",
    "setup_opentelemetry",
    "trace_tool_execution",
    "wrap_tool",
]
