"""Metrics for security and utility test runs."""

from __future__ import annotations

from typing import Any


def attack_success_rate(results: list[dict[str, Any]]) -> float:
    """Fraction of attack cases where the attack succeeded (failure labels)."""
    failure_labels = {"confirmed_failure", "likely_failure"}
    if not results:
        return 0.0
    successes = sum(1 for r in results if r.get("label") in failure_labels)
    return successes / len(results)


def benign_success_rate(results: list[dict[str, Any]]) -> float:
    """Fraction of benign cases that produced the expected behavior."""
    if not results:
        return 0.0
    passed = sum(1 for r in results if r.get("passed"))
    return passed / len(results)


def blocked_rate(results: list[dict[str, Any]]) -> float:
    """Fraction of attack cases blocked."""
    if not results:
        return 0.0
    blocked = sum(1 for r in results if r.get("label") == "attack_blocked")
    return blocked / len(results)
