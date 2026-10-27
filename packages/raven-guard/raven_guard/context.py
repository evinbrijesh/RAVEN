"""Context management for raven-guard security tokens and session state."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Generator

from raven_guard.models import SecurityContext

_CURRENT_CONTEXT: ContextVar[SecurityContext | None] = ContextVar(
    "raven_guard_security_context", default=None
)


def get_current_context() -> SecurityContext | None:
    """Retrieve the currently active security context for this async task or thread."""
    return _CURRENT_CONTEXT.get()


def set_current_context(context: SecurityContext | dict[str, Any] | None) -> Token[SecurityContext | None]:
    """Set the current security context, returning a token to reset it."""
    ctx = SecurityContext.from_any(context) if context is not None else None
    return _CURRENT_CONTEXT.set(ctx)


def reset_current_context(token: Token[SecurityContext | None]) -> None:
    """Reset the security context to its previous value via its token."""
    _CURRENT_CONTEXT.reset(token)


@contextmanager
def security_context(
    context: SecurityContext | dict[str, Any] | None = None,
    **kwargs: Any,
) -> Generator[SecurityContext, None, None]:
    """Context manager for setting an active SecurityContext within a block.

    Example:
        with security_context(verified_user=True, verified_order_id=True):
            my_protected_tool(order_id="ORD-1")
    """
    if context is not None and kwargs:
        ctx_dict = context.to_dict() if hasattr(context, "to_dict") else dict(context)
        ctx_dict.update(kwargs)
        active_ctx = SecurityContext.from_any(ctx_dict)
    elif context is not None:
        active_ctx = SecurityContext.from_any(context)
    else:
        active_ctx = SecurityContext.from_any(kwargs)

    token = set_current_context(active_ctx)
    try:
        yield active_ctx
    finally:
        reset_current_context(token)
