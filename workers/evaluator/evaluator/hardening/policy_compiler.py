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
        # MVP keeps the default threshold; per-finding thresholds are post-MVP.
        return candidate
