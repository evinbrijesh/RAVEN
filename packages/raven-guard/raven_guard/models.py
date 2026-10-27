"""Data models and value objects for raven-guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Decision:
    """Represents the authorization decision rendered by PolicyGateway."""

    allowed: bool
    reason: str
    tool: str = ""
    policy_source: str = "gateway_default"
    violations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """Allow intuitive pythonic boolean checks: if not decision: ..."""
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "tool": self.tool,
            "policy_source": self.policy_source,
            "violations": list(self.violations),
            "metadata": dict(self.metadata),
        }


@dataclass
class SecurityContext:
    """Contextual metadata passed during tool authorization."""

    verified_user: bool = False
    verified_order_id: bool = False
    user_id: str | None = None
    order_id: str | None = None
    amount: float | None = None
    roles: list[str] = field(default_factory=list)
    session_id: str | None = None
    user_message: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_any(cls, obj: Any) -> SecurityContext:
        """Coerces None, dict, dataclass, or attribute-bearing object into a SecurityContext."""
        if obj is None:
            return cls()
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, dict):
            extra = {
                k: v
                for k, v in obj.items()
                if k
                not in (
                    "verified_user",
                    "verified_order_id",
                    "user_id",
                    "order_id",
                    "amount",
                    "roles",
                    "session_id",
                    "user_message",
                )
            }
            return cls(
                verified_user=bool(obj.get("verified_user", False)),
                verified_order_id=bool(obj.get("verified_order_id", False)),
                user_id=obj.get("user_id"),
                order_id=obj.get("order_id"),
                amount=float(obj["amount"]) if obj.get("amount") is not None else None,
                roles=list(obj.get("roles", [])),
                session_id=obj.get("session_id"),
                user_message=obj.get("user_message"),
                extra=extra,
            )

        # Object with attributes (e.g. ToolContext from evaluator)
        return cls(
            verified_user=bool(getattr(obj, "verified_user", False)),
            verified_order_id=bool(getattr(obj, "verified_order_id", False)),
            user_id=getattr(obj, "user_id", None),
            order_id=getattr(obj, "order_id", None),
            amount=getattr(obj, "amount", None),
            roles=list(getattr(obj, "roles", [])),
            session_id=getattr(obj, "session_id", None),
            user_message=getattr(obj, "user_message", None),
            extra=getattr(obj, "extra", {}) if isinstance(getattr(obj, "extra", None), dict) else {},
        )


@dataclass
class ToolPolicy:
    """Policy rules governing a specific tool."""

    tool: str
    conditions: list[str] = field(default_factory=list)
    high_value_action: str = "none"
    amount_threshold: float | None = None
    parameter_rules: dict[str, Any] = field(default_factory=dict)
    allowed_roles: list[str] = field(default_factory=list)
    on_violation: str = "deny_and_log"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolPolicy:
        threshold = data.get("amount_threshold")
        return cls(
            tool=str(data.get("tool", "")),
            conditions=list(data.get("conditions", [])),
            high_value_action=str(data.get("high_value_action", "none")),
            amount_threshold=float(threshold) if threshold is not None else None,
            parameter_rules=dict(data.get("parameter_rules", {})),
            allowed_roles=list(data.get("allowed_roles", [])),
            on_violation=str(data.get("on_violation", "deny_and_log")),
        )


@dataclass
class PolicyDocument:
    """Complete policy document compiled by RAVEN or authored by engineers."""

    version: str = "v1"
    description: str = ""
    fail_closed: bool = True
    tools: dict[str, ToolPolicy] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyDocument:
        tools: dict[str, ToolPolicy] = {}
        for entry in data.get("tools", []):
            if isinstance(entry, dict) and "tool" in entry:
                tools[entry["tool"]] = ToolPolicy.from_dict(entry)
            elif isinstance(entry, ToolPolicy):
                tools[entry.tool] = entry

        return cls(
            version=str(data.get("version", "v1")),
            description=str(data.get("description", "")),
            fail_closed=bool(data.get("fail_closed", True)),
            tools=tools,
        )
