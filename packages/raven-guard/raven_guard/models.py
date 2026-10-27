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
    claims: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def get_claim(self, key: str, default: Any = None) -> Any:
        """Retrieve a claim from explicit claims, direct attributes, or extra dictionary."""
        if key in self.claims:
            return self.claims[key]
        if hasattr(self, key):
            val = getattr(self, key)
            if val is not None:
                return val
        if key in self.extra:
            return self.extra[key]
        return default

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified_user": self.verified_user,
            "verified_order_id": self.verified_order_id,
            "user_id": self.user_id,
            "order_id": self.order_id,
            "amount": self.amount,
            "roles": list(self.roles),
            "session_id": self.session_id,
            "user_message": self.user_message,
            "claims": dict(self.claims),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_any(cls, obj: Any) -> SecurityContext:
        """Coerces None, dict, dataclass, or attribute-bearing object into a SecurityContext."""
        if obj is None:
            return cls()
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, dict):
            known_keys = (
                "verified_user",
                "verified_order_id",
                "user_id",
                "order_id",
                "amount",
                "roles",
                "session_id",
                "user_message",
                "claims",
            )
            extra = {k: v for k, v in obj.items() if k not in known_keys}
            claims = dict(obj.get("claims", {})) if isinstance(obj.get("claims"), dict) else {}
            # Automatically mirror core identifiers into claims if not already present
            if obj.get("user_id") and "user_id" not in claims:
                claims["user_id"] = obj["user_id"]
            if obj.get("order_id") and "order_id" not in claims:
                claims["order_id"] = obj["order_id"]
            if obj.get("session_id") and "session_id" not in claims:
                claims["session_id"] = obj["session_id"]
            if "tenant_id" in extra and "tenant_id" not in claims:
                claims["tenant_id"] = extra["tenant_id"]

            return cls(
                verified_user=bool(obj.get("verified_user", False)),
                verified_order_id=bool(obj.get("verified_order_id", False)),
                user_id=obj.get("user_id"),
                order_id=obj.get("order_id"),
                amount=float(obj["amount"]) if obj.get("amount") is not None else None,
                roles=list(obj.get("roles", [])),
                session_id=obj.get("session_id"),
                user_message=obj.get("user_message"),
                claims=claims,
                extra=extra,
            )

        # Object with attributes (e.g. ToolContext from evaluator or custom class)
        claims_attr = getattr(obj, "claims", {})
        claims = dict(claims_attr) if isinstance(claims_attr, dict) else {}
        uid = getattr(obj, "user_id", None)
        oid = getattr(obj, "order_id", None)
        sid = getattr(obj, "session_id", None)
        if uid and "user_id" not in claims:
            claims["user_id"] = uid
        if oid and "order_id" not in claims:
            claims["order_id"] = oid
        if sid and "session_id" not in claims:
            claims["session_id"] = sid

        extra_attr = getattr(obj, "extra", {})
        extra = dict(extra_attr) if isinstance(extra_attr, dict) else {}
        if "tenant_id" in extra and "tenant_id" not in claims:
            claims["tenant_id"] = extra["tenant_id"]

        return cls(
            verified_user=bool(getattr(obj, "verified_user", False)),
            verified_order_id=bool(getattr(obj, "verified_order_id", False)),
            user_id=uid,
            order_id=oid,
            amount=getattr(obj, "amount", None),
            roles=list(getattr(obj, "roles", [])),
            session_id=sid,
            user_message=getattr(obj, "user_message", None),
            claims=claims,
            extra=extra,
        )


# Backward-compatible alias
PolicyContext = SecurityContext


@dataclass
class ToolPolicy:
    """Policy rules governing a specific tool."""

    tool: str
    conditions: list[str] = field(default_factory=list)
    high_value_action: str = "none"
    amount_threshold: float | None = None
    parameter_rules: dict[str, Any] = field(default_factory=dict)
    allowed_roles: list[str] = field(default_factory=list)
    context_claims: dict[str, str] = field(default_factory=dict)
    on_violation: str = "deny_and_log"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolPolicy:
        threshold = data.get("amount_threshold")
        claims_mapping = data.get("context_claims", data.get("claims_mapping", {}))
        return cls(
            tool=str(data.get("tool", "")),
            conditions=list(data.get("conditions", [])),
            high_value_action=str(data.get("high_value_action", "none")),
            amount_threshold=float(threshold) if threshold is not None else None,
            parameter_rules=dict(data.get("parameter_rules", {})),
            allowed_roles=list(data.get("allowed_roles", [])),
            context_claims=dict(claims_mapping) if isinstance(claims_mapping, dict) else {},
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
        raw_tools = data.get("tools", [])
        if isinstance(raw_tools, dict):
            for tool_name, spec in raw_tools.items():
                if isinstance(spec, dict):
                    tool_data = dict(spec)
                    tool_data.setdefault("tool", tool_name)
                    tools[tool_name] = ToolPolicy.from_dict(tool_data)
                elif isinstance(spec, ToolPolicy):
                    tools[tool_name] = spec
        elif isinstance(raw_tools, (list, tuple)):
            for entry in raw_tools:
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
