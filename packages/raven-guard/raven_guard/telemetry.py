"""Structured security audit telemetry for raven-guard."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger("raven_guard.security")

TelemetryListener = Callable[[dict[str, Any]], None]
_LISTENERS: list[TelemetryListener] = []


def register_telemetry_listener(listener: TelemetryListener) -> None:
    """Register a custom telemetry listener callback for security audit events."""
    if listener not in _LISTENERS:
        _LISTENERS.append(listener)


def unregister_telemetry_listener(listener: TelemetryListener) -> None:
    """Remove a previously registered telemetry listener."""
    if listener in _LISTENERS:
        _LISTENERS.remove(listener)


def clear_telemetry_listeners() -> None:
    """Clear all registered telemetry listeners."""
    _LISTENERS.clear()


@dataclass
class SecurityAuditEvent:
    """Structured security telemetry event."""

    event_type: str
    tool: str
    allowed: bool
    reason: str
    violations: list[str] = field(default_factory=list)
    arguments: dict[str, Any] = field(default_factory=dict)
    user_id: str | None = None
    session_id: str | None = None
    claims_summary: dict[str, Any] = field(default_factory=dict)
    policy_source: str = "gateway_default"
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


def emit_security_event(event: SecurityAuditEvent) -> None:
    """Emits a structured audit event to the security logger and active listeners."""
    payload = event.to_dict()

    # Log structured event
    log_msg = f"[RAVEN-GUARD-AUDIT] {event.event_type.upper()} | tool={event.tool} allowed={event.allowed} reason={event.reason}"
    if not event.allowed:
        logger.warning(
            "%s | violations=%s | args=%s | user=%s",
            log_msg,
            event.violations,
            event.arguments,
            event.user_id,
            extra={"security_event": payload},
        )
    else:
        logger.info(
            "%s | user=%s",
            log_msg,
            event.user_id,
            extra={"security_event": payload},
        )

    # Dispatch to listeners
    for listener in list(_LISTENERS):
        try:
            listener(payload)
        except Exception as exc:
            logger.debug("Telemetry listener error: %s", exc)
