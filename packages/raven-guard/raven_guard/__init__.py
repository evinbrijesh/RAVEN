"""raven-guard: Deterministic, fail-closed runtime policy gateway for LLM tool calling."""

from raven_guard.context import (
    get_current_context,
    reset_current_context,
    security_context,
    set_current_context,
)
from raven_guard.errors import (
    ApprovalRequiredError,
    MalformedArgumentsError,
    PolicyConfigurationError,
    PolicyViolationError,
    RavenGuardError,
)
from raven_guard.gateway import PolicyGateway
from raven_guard.integrations import (
    OpenTelemetrySecurityListener,
    RavenGuardCallbackHandler,
    RavenGuardMiddleware,
    RavenGuardToolNode,
    RavenToolInterceptor,
    setup_opentelemetry,
    trace_tool_execution,
    wrap_tool,
)
from raven_guard.loader import (
    find_default_policy,
    load_policy,
    load_policy_file,
    parse_policy_string,
)
from raven_guard.models import (
    Decision,
    PolicyContext,
    PolicyDocument,
    SecurityContext,
    ToolPolicy,
)
from raven_guard.telemetry import (
    SecurityAuditEvent,
    clear_telemetry_listeners,
    register_telemetry_listener,
    unregister_telemetry_listener,
)

__version__ = "1.0.0"

__all__ = [
    "ApprovalRequiredError",
    "Decision",
    "MalformedArgumentsError",
    "OpenTelemetrySecurityListener",
    "PolicyConfigurationError",
    "PolicyContext",
    "PolicyDocument",
    "PolicyGateway",
    "PolicyViolationError",
    "RavenGuardCallbackHandler",
    "RavenGuardError",
    "RavenGuardMiddleware",
    "RavenGuardToolNode",
    "RavenToolInterceptor",
    "SecurityAuditEvent",
    "SecurityContext",
    "ToolPolicy",
    "clear_telemetry_listeners",
    "find_default_policy",
    "get_current_context",
    "load_policy",
    "load_policy_file",
    "parse_policy_string",
    "register_telemetry_listener",
    "reset_current_context",
    "security_context",
    "set_current_context",
    "setup_opentelemetry",
    "trace_tool_execution",
    "unregister_telemetry_listener",
    "wrap_tool",
]
