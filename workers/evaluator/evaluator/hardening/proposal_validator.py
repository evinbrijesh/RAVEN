"""Proposal validator: rejects malformed or unsafe hardening proposals.

A proposal may only reach the approval step if it passes this validator
(definition of done §4: cannot bypass the safety policy).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.domain.entities import HardeningProposal
from app.domain.errors import UnsafeOperation

from evaluator.hardening.policy_compiler import POLICY_TOOL_ALLOWLIST

# Strings that must never appear in a proposal diff (deploy/execute verbs).
FORBIDDEN_DIFF_MARKERS: tuple[str, ...] = (
    "deploy to production",
    "push to prod",
    "rm -rf",
    "curl ",
    "wget ",
    "os.system",
    "subprocess",
)


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ProposalValidator:
    """Static safety validation for hardening proposals."""

    def validate(self, proposal: HardeningProposal) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        if not proposal.prompt_diff.strip():
            errors.append("prompt_diff is empty")
        lowered = proposal.prompt_diff.lower()
        for marker in FORBIDDEN_DIFF_MARKERS:
            if marker in lowered:
                errors.append(f"prompt_diff contains forbidden marker: '{marker}'")

        if not proposal.rationale.strip():
            errors.append("rationale is empty")
        if not proposal.affected_cases:
            warnings.append("no affected cases listed")

        candidate = proposal.policy_candidate
        if candidate is not None:
            if candidate.tool not in POLICY_TOOL_ALLOWLIST:
                errors.append(
                    f"policy tool '{candidate.tool}' is not in the simulated tool allowlist"
                )
            if not candidate.conditions:
                errors.append("policy candidate has no conditions (would fail open)")
            if candidate.on_violation not in {"deny_and_log", "deny"}:
                errors.append(f"on_violation '{candidate.on_violation}' is not fail-closed")

        return ValidationResult(valid=not errors, errors=errors, warnings=warnings)

    def validate_or_raise(self, proposal: HardeningProposal) -> ValidationResult:
        result = self.validate(proposal)
        if not result.valid:
            raise UnsafeOperation(
                "Hardening proposal failed safety validation.",
                details={"errors": result.errors},
            )
        return result
