"""Exception hierarchy for raven-guard runtime policy gateway."""

from __future__ import annotations

from typing import Any


class RavenGuardError(Exception):
    """Base exception for all raven-guard runtime errors."""


class PolicyConfigurationError(RavenGuardError, ValueError):
    """Raised when policy definitions or files are malformed."""


class PolicyViolationError(RavenGuardError, PermissionError):
    """Raised when an action or tool invocation violates the active policy."""

    def __init__(
        self,
        message: str,
        tool: str,
        reason: str,
        decision: Any = None,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.tool = tool
        self.reason = reason
        self.decision = decision
        self.arguments = arguments or {}


class ApprovalRequiredError(PolicyViolationError):
    """Raised when an operation requires explicit human-in-the-loop approval."""


class MalformedArgumentsError(PolicyViolationError):
    """Raised when arguments violate basic type or boundary constraints."""
