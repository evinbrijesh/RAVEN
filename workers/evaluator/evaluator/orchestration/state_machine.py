"""Scan state machine (blueprint §6).

Statuses follow docs/CLAUDE.md. The blueprint's REGRESSION_SAVED and REPORTING
steps are modeled as events inside the RETESTING phase, not as extra statuses,
to keep the status enum aligned with the project conventions.
"""

from __future__ import annotations

from app.domain.entities import Scan
from app.domain.enums import ScanStatus
from app.domain.errors import InvalidTransition

ALLOWED_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.CREATED: {ScanStatus.RECONNING, ScanStatus.FAILED_FATAL},
    ScanStatus.RECONNING: {ScanStatus.ATTACKING, ScanStatus.FAILED_PARTIAL, ScanStatus.FAILED_FATAL},
    ScanStatus.ATTACKING: {ScanStatus.JUDGING, ScanStatus.FAILED_PARTIAL, ScanStatus.FAILED_FATAL},
    ScanStatus.JUDGING: {
        ScanStatus.HARDENING_PROPOSED,
        ScanStatus.COMPLETED,  # no findings -> nothing to harden
        ScanStatus.COMPLETED_WITH_LIMITATIONS,
        ScanStatus.INCONCLUSIVE,
        ScanStatus.FAILED_PARTIAL,
        ScanStatus.FAILED_FATAL,
    },
    ScanStatus.HARDENING_PROPOSED: {ScanStatus.AWAITING_APPROVAL, ScanStatus.FAILED_PARTIAL},
    ScanStatus.AWAITING_APPROVAL: {
        ScanStatus.RETESTING,
        ScanStatus.COMPLETED_WITHOUT_RETEST,
        ScanStatus.COMPLETED_WITH_LIMITATIONS,
        ScanStatus.INCONCLUSIVE,
        ScanStatus.FAILED_PARTIAL,
        ScanStatus.FAILED_FATAL,
    },
    ScanStatus.RETESTING: {
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED_WITH_LIMITATIONS,
        ScanStatus.INCONCLUSIVE,
        ScanStatus.FAILED_PARTIAL,
        ScanStatus.FAILED_FATAL,
    },
    ScanStatus.COMPLETED: set(),
    ScanStatus.COMPLETED_WITHOUT_RETEST: set(),
    ScanStatus.COMPLETED_WITH_LIMITATIONS: set(),
    ScanStatus.FAILED_PARTIAL: set(),
    ScanStatus.FAILED_FATAL: set(),
    ScanStatus.INCONCLUSIVE: set(),
}

TERMINAL_STATUSES = {
    ScanStatus.COMPLETED,
    ScanStatus.COMPLETED_WITHOUT_RETEST,
    ScanStatus.COMPLETED_WITH_LIMITATIONS,
    ScanStatus.FAILED_PARTIAL,
    ScanStatus.FAILED_FATAL,
    ScanStatus.INCONCLUSIVE,
}


def can_transition(current: ScanStatus, target: ScanStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())


def transition(scan: Scan, target: ScanStatus) -> Scan:
    """Validate and apply a status transition on a Scan entity (in memory)."""
    if scan.status == target:
        return scan
    if not can_transition(scan.status, target):
        raise InvalidTransition(
            f"Illegal transition {scan.status.value} -> {target.value}",
            details={"scan_id": scan.scan_id},
        )
    scan.status = target
    return scan


def is_terminal(status: ScanStatus) -> bool:
    return status in TERMINAL_STATUSES
