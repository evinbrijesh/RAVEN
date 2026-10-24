"""Redaction and limit enforcement tests."""

from __future__ import annotations

from app.domain.entities import ScanConfig
from app.domain.errors import TargetNotAllowed, ValidationFailed
from app.domain.value_objects import Budget
from app.security.limits import clamp_budget, validate_scan_config
from app.security.redaction import redact, redact_mapping


def test_redact_email_and_api_key() -> None:
    text = "contact demo@example.com or key sk-abcdef1234567890"
    out = redact(text)
    assert "demo@example.com" not in out
    assert "sk-abcdef" not in out
    assert "[REDACTED:email]" in out
    assert "[REDACTED:api_key]" in out


def test_redact_mapping() -> None:
    out = redact_mapping({"note": "call 555-123-4567", "count": 2})
    assert "555-123-4567" not in out["note"]  # type: ignore[operator]
    assert out["count"] == 2


def test_clamp_budget_enforces_hard_caps() -> None:
    clamped = clamp_budget(
        Budget(max_attack_cases=99, max_attempts_per_attack=9, max_model_calls=9999)
    )
    assert clamped.max_attack_cases == 12
    assert clamped.max_attempts_per_attack == 2
    assert clamped.max_model_calls == 200


def test_validate_scan_config_rejects_unknown_target() -> None:
    try:
        validate_scan_config(ScanConfig(target_id="http://attacker.example"))
    except TargetNotAllowed:
        pass  # expected
    else:
        raise AssertionError("unknown target must be rejected")


def test_validate_scan_config_rejects_mutation_without_model_budget() -> None:
    config = ScanConfig(
        target_id="shophelper-local",
        enable_mutation=True,
        budget=Budget(max_model_calls=0),
    )
    try:
        validate_scan_config(config)
    except ValidationFailed:
        pass  # expected
    else:
        raise AssertionError("mutation with zero model budget must be rejected")


def test_validate_scan_config_clamps_budget() -> None:
    config = validate_scan_config(
        ScanConfig(
            target_id="shophelper-local",
            budget=Budget(max_attack_cases=50, max_attempts_per_attack=7),
        )
    )
    assert config.budget.max_attack_cases == 12
    assert config.budget.max_attempts_per_attack == 2
