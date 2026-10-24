"""Runtime limit enforcement (blueprint §8 controls 5–10)."""

from __future__ import annotations

from app.domain.entities import ScanConfig
from app.domain.errors import ValidationFailed
from app.domain.value_objects import Budget

# Hard caps — a scan config cannot exceed these even if its Budget asks for more.
HARD_MAX_ATTACK_CASES = 12
HARD_MAX_ATTEMPTS_PER_ATTACK = 2
HARD_MAX_MODEL_CALLS = 200
HARD_MAX_TOTAL_TOKENS = 1_000_000
HARD_MAX_SCAN_TIMEOUT_SECONDS = 3_600.0
HARD_MAX_CONCURRENCY = 8


def clamp_budget(budget: Budget) -> Budget:
    """Clamp a requested budget to the hard caps."""
    return Budget(
        max_attack_cases=min(budget.max_attack_cases, HARD_MAX_ATTACK_CASES),
        max_attempts_per_attack=min(
            budget.max_attempts_per_attack, HARD_MAX_ATTEMPTS_PER_ATTACK
        ),
        max_model_calls=min(budget.max_model_calls, HARD_MAX_MODEL_CALLS),
        max_total_tokens=min(budget.max_total_tokens, HARD_MAX_TOTAL_TOKENS),
        per_call_timeout_seconds=budget.per_call_timeout_seconds,
        scan_timeout_seconds=min(
            budget.scan_timeout_seconds, HARD_MAX_SCAN_TIMEOUT_SECONDS
        ),
        concurrency_limit=min(budget.concurrency_limit, HARD_MAX_CONCURRENCY),
    )


def validate_scan_config(config: ScanConfig) -> ScanConfig:
    """Validate a scan config against the runtime limits. Raises on violation."""
    from app.security.authorization import assert_target_allowed

    assert_target_allowed(config.target_id)

    if len(config.attack_categories) > 4:
        raise ValidationFailed(
            "At most 4 attack categories are supported in the MVP.",
            details={"categories": [c.value for c in config.attack_categories]},
        )
    if config.max_attempts_per_attack > HARD_MAX_ATTEMPTS_PER_ATTACK:
        raise ValidationFailed(
            f"max_attempts_per_attack must be <= {HARD_MAX_ATTEMPTS_PER_ATTACK}."
        )
    if config.budget.max_attack_cases > HARD_MAX_ATTACK_CASES:
        raise ValidationFailed(
            f"max_attack_cases must be <= {HARD_MAX_ATTACK_CASES}."
        )
    if config.enable_mutation and config.budget.max_model_calls == 0:
        raise ValidationFailed(
            "Mutation must be disabled if the model budget is exhausted."
        )
    return config.model_copy(update={"budget": clamp_budget(config.budget)})
