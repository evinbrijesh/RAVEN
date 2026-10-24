"""Budget tracking (blueprint §8 controls 5–10).

Every model call and attempt must be accounted for; exceeding a budget raises
BudgetExceeded and the scan degrades to deterministic-only behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.domain.errors import BudgetExceeded
from app.domain.value_objects import Budget


@dataclass
class BudgetTracker:
    budget: Budget
    model_calls_used: int = 0
    tokens_used: int = 0
    attempts_used: dict[str, int] = field(default_factory=dict)

    @property
    def model_calls_remaining(self) -> int:
        return max(0, self.budget.max_model_calls - self.model_calls_used)

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.budget.max_total_tokens - self.tokens_used)

    def attempts_remaining(self, attack_case_id: str) -> int:
        used = self.attempts_used.get(attack_case_id, 0)
        return max(0, self.budget.max_attempts_per_attack - used)

    def consume_attempt(self, attack_case_id: str) -> None:
        if self.attempts_remaining(attack_case_id) <= 0:
            raise BudgetExceeded(
                f"Attempt budget exhausted for attack case '{attack_case_id}'."
            )
        self.attempts_used[attack_case_id] = self.attempts_used.get(attack_case_id, 0) + 1

    def consume_model_call(self, tokens: int = 0) -> None:
        if self.model_calls_remaining <= 0:
            raise BudgetExceeded("Model-call budget exhausted.")
        if tokens > self.tokens_remaining:
            raise BudgetExceeded("Token budget exhausted.")
        self.model_calls_used += 1
        self.tokens_used += tokens

    def record_tokens(self, input_tokens: int, output_tokens: int) -> None:
        """Post-hoc token accounting for a call already counted (H4 fix).

        The call slot is reserved before the request; actual usage is recorded
        afterwards so max_total_tokens is enforced on the next reservation.
        """
        self.tokens_used += max(0, input_tokens) + max(0, output_tokens)

    def snapshot(self) -> dict[str, int]:
        return {
            "model_calls_used": self.model_calls_used,
            "model_calls_remaining": self.model_calls_remaining,
            "tokens_used": self.tokens_used,
            "tokens_remaining": self.tokens_remaining,
        }
