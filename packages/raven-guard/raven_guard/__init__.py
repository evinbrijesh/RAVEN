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
    RavenGuardCallbackHandler,
    RavenGuardToolNode,
    RavenToolInterceptor,
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

__version__ = "0.1.0"

__all__ = [
    "PolicyGateway",
    "Decision",
    "SecurityContext",
    "ToolPolicy",
    "PolicyDocument",
    "RavenGuardError",
    "PolicyViolationError",
    "ApprovalRequiredError",
    "MalformedArgumentsError",
    "PolicyConfigurationError",
    "security_context",
    "set_current_context",
    "get_current_context",
    "reset_current_context",
    "load_policy",
    "load_policy_file",
    "parse_policy_string",
    "find_default_policy",
    "RavenGuardToolNode",
    "RavenGuardCallbackHandler",
    "RavenToolInterceptor",
    "wrap_tool",
    "SecurityAuditEvent",
    "register_telemetry_listener",
    "unregister_telemetry_listener",
    "clear_telemetry_listeners",
]
