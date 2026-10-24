"""Target authorization.

Rule 1 (docs/CLAUDE.md): never implement scanning of arbitrary third-party
targets in the MVP. The allowlist is enforced here and re-checked in the
Scan entity validator (defense in depth).
"""

from __future__ import annotations

from app.domain.errors import TargetNotAllowed

# Built-in target allowlist (blueprint §8 control 1).
TARGET_ALLOWLIST: frozenset[str] = frozenset({"shophelper-local"})


def assert_target_allowed(target_id: str) -> None:
    if target_id not in TARGET_ALLOWLIST:
        raise TargetNotAllowed(
            f"Target '{target_id}' is not in the built-in allowlist.",
            details={"allowed": sorted(TARGET_ALLOWLIST)},
        )


def is_target_allowed(target_id: str) -> bool:
    return target_id in TARGET_ALLOWLIST
