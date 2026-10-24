"""Fail-closed policy gateway for the simulated ShopHelper tools.

The gateway is the enforcement point for tool calls inside the evaluation
target. It must fail closed and must never perform real external actions
(docs/ARCHITECTURE.md §7).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evaluator.targets.base import PolicyDecision, ToolContext

REFUSAL_REASON = "denied_by_policy_gateway"


class PolicyGateway:
    """Authorizes tool calls against the active policy candidate. Fail closed."""

    def __init__(self, policy: dict[str, Any]) -> None:
        self._policies: dict[str, dict[str, Any]] = {}
        self.decisions: list[dict[str, Any]] = []
        self.load(policy)

    def load(self, policy: dict[str, Any]) -> None:
        """Load a policy document: {"tools": [{...candidate...}, ...]}."""
        for entry in policy.get("tools", []):
            self._policies[entry["tool"]] = entry

    def apply_candidate(self, candidate: dict[str, Any]) -> None:
        """Apply a compiled PolicyCandidate for its tool (replaces prior rules)."""
        self._policies[candidate["tool"]] = candidate

    def clear(self) -> None:
        self._policies.clear()
        self.decisions.clear()

    def authorize(self, tool_name: str, arguments: dict[str, Any], context: ToolContext) -> PolicyDecision:
        policy = self._policies.get(tool_name)
        # Fail closed: no policy for this tool -> deny.
        if policy is None:
            decision = PolicyDecision(
                allowed=False,
                reason=f"no_policy_for_tool:{tool_name}",
                policy_source="gateway_default",
            )
            self._record(tool_name, arguments, decision)
            return decision

        for condition in policy.get("conditions", []):
            ok, reason = self._check_condition(condition, arguments, context, policy)
            if not ok:
                decision = PolicyDecision(allowed=False, reason=reason, policy_source="candidate")
                self._record(tool_name, arguments, decision)
                return decision

        decision = PolicyDecision(allowed=True, reason="all_conditions_met", policy_source="candidate")
        self._record(tool_name, arguments, decision)
        return decision

    @staticmethod
    def _check_condition(
        condition: str, arguments: dict[str, Any], context: ToolContext, policy: dict[str, Any]
    ) -> tuple[bool, str]:
        checks = {
            "verified_order_id_present": (
                context.verified_order_id or bool(arguments.get("order_id")),
                "missing_verified_order_id",
            ),
            "verified_user_present": (
                context.verified_user,
                "missing_verified_user",
            ),
            "amount_below_threshold": (
                context.amount is not None
                and context.amount < float(policy.get("amount_threshold", 100.0)),
                "amount_at_or_above_threshold",
            ),
        }
        if condition not in checks:
            return False, f"unknown_condition:{condition}"
        ok, reason = checks[condition]
        return ok, reason

    def _record(self, tool_name: str, arguments: dict[str, Any], decision: PolicyDecision) -> None:
        self.decisions.append(
            {
                "tool": tool_name,
                "arguments": arguments,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "policy_source": decision.policy_source,
            }
        )


def load_policy_file(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"Policy file must contain an object: {path}")
    return data
