"""RAVEN domain errors.

Every error carries a stable machine-readable code so the API can return the
error format defined in docs/API_CONTRACT.md §9.
"""

from __future__ import annotations

from typing import Any


class RavenError(Exception):
    """Base class for all RAVEN domain errors."""

    code = "RAVEN_ERROR"
    retryable = False

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details,
        }


class NotFoundError(RavenError):
    code = "NOT_FOUND"


class ValidationFailed(RavenError):
    code = "VALIDATION_FAILED"


class TargetNotAllowed(RavenError):
    """Raised when a scan requests a target outside the built-in allowlist."""

    code = "TARGET_NOT_ALLOWED"


class BudgetExceeded(RavenError):
    code = "BUDGET_EXCEEDED"
    retryable = False


class InvalidTransition(RavenError):
    """Raised when a scan state transition is not allowed."""

    code = "INVALID_TRANSITION"


class ModelUnavailable(RavenError):
    """Model provider failed or timed out; deterministic checks continue."""

    code = "MODEL_UNAVAILABLE"
    retryable = True


class ModelSchemaViolation(RavenError):
    """Model output failed strict schema validation (after one retry)."""

    code = "MODEL_SCHEMA_VIOLATION"
    retryable = False


class ApprovalRequired(RavenError):
    """A policy candidate cannot be applied without explicit human approval."""

    code = "APPROVAL_REQUIRED"


class UnsafeOperation(RavenError):
    """An operation attempted to bypass the runtime safety policy."""

    code = "UNSAFE_OPERATION"
