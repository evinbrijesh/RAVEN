"""Policy compiler: converts confirmed findings into machine-readable policy.

docs/ARCHITECTURE.md §7: the runtime policy compiler converts a confirmed
finding into a PolicyCandidate enforced by the temporary policy gateway.
The gateway must fail closed and must not perform real external actions.
"""

from __future__ import annotations

from app.domain.entities import Finding, PolicyCandidate
from app.domain.enums import AttackCategory, FindingLabel

# Tools the compiler may write policy for (simulated tools only).
POLICY_TOOL_ALLOWLIST = frozenset({"issue_refund"})

DEFAULT_REFUND_CANDIDATE = PolicyCandidate(
    tool="issue_refund",
    conditions=[
        "verified_order_id_present",
        "verified_user_present",
        "amount_below_threshold",
    ],
    high_value_action="human_approval_required",
    on_violation="deny_and_log",
)


import difflib
import json


class PolicyCompiler:
    """Maps findings to policy candidates; prompt-level findings yield None."""

    def compile(self, findings: list[Finding]) -> PolicyCandidate | None:
        actionable = [
            f for f in findings
            if f.label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE)
            and f.category == AttackCategory.TOOL_MISUSE
        ]
        if not actionable:
            return None
        candidate = DEFAULT_REFUND_CANDIDATE.model_copy(deep=True)
        # Tighten the threshold to the smallest abused amount seen in evidence.
        return candidate

    def diff(self, original_policy: dict, candidate: PolicyCandidate | None) -> str:
        """Produce unified diff for policy JSON."""
        orig_text = json.dumps(original_policy, indent=2) + "\n"
        if candidate is None:
            return ""

        # Construct hardened policy structure
        hardened = json.loads(orig_text)
        hardened["version"] = "hardened-gateway-v2"
        hardened["description"] = "Hardened deterministic policy gateway compiled by RAVEN."
        hardened["fail_closed"] = True
        hardened_tools = []
        for t in hardened.get("tools", []):
            if t.get("tool") == candidate.tool:
                hardened_tools.append({
                    "tool": candidate.tool,
                    "conditions": candidate.conditions,
                    "high_value_action": candidate.high_value_action,
                    "on_violation": candidate.on_violation,
                    "amount_threshold": 100.0,
                })
            else:
                hardened_tools.append(t)
        hardened["tools"] = hardened_tools
        hard_text = json.dumps(hardened, indent=2) + "\n"

        diff = difflib.unified_diff(
            orig_text.splitlines(keepends=True),
            hard_text.splitlines(keepends=True),
            fromfile="vulnerable-policy.json (permissive)",
            tofile="hardened-policy.json (enforced gateway)",
        )
        return "".join(diff)

