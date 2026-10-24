"""RAVEN domain enumerations.

Statuses and labels follow docs/CLAUDE.md "State and status conventions".
"""

from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    """Explicit scan lifecycle statuses."""

    CREATED = "created"
    RECONNING = "reconning"
    ATTACKING = "attacking"
    JUDGING = "judging"
    HARDENING_PROPOSED = "hardening_proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    RETESTING = "retesting"
    COMPLETED = "completed"
    COMPLETED_WITHOUT_RETEST = "completed_without_retest"
    COMPLETED_WITH_LIMITATIONS = "completed_with_limitations"
    FAILED_PARTIAL = "failed_partial"
    FAILED_FATAL = "failed_fatal"
    INCONCLUSIVE = "inconclusive"


class FindingLabel(StrEnum):
    """Explicit finding labels."""

    CONFIRMED_FAILURE = "confirmed_failure"
    LIKELY_FAILURE = "likely_failure"
    ATTACK_BLOCKED = "attack_blocked"
    NEEDS_REVIEW = "needs_review"
    PARTIAL_MITIGATION = "partial_mitigation"
    REGRESSION_DETECTED = "regression_detected"
    NOT_EVALUATED = "not_evaluated"
    VERIFIED_UNDER_STATED_CHECKS = "verified_under_stated_checks"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(StrEnum):
    """The four MVP attack categories."""

    DIRECT_INJECTION = "direct_injection"
    CANARY_LEAKAGE = "canary_leakage"
    SENSITIVE_DATA = "sensitive_data"
    TOOL_MISUSE = "tool_misuse"


class JudgeRole(StrEnum):
    """Model-plane roles. Attacker and judge must stay separate."""

    ATTACKER = "attacker"
    JUDGE = "judge"
    HARDENER = "hardener"
    CLASSIFIER = "classifier"


class EventKind(StrEnum):
    """Scan event kinds emitted to the SSE stream."""

    SCAN_CREATED = "scan_created"
    PHASE_CHANGED = "phase_changed"
    RECON_COMPLETED = "recon_completed"
    ATTACK_STARTED = "attack_started"
    ATTACK_FINISHED = "attack_finished"
    VERDICT_CREATED = "verdict_created"
    HARDENING_PROPOSED = "hardening_proposed"
    APPROVAL_RECEIVED = "approval_received"
    RETEST_STARTED = "retest_started"
    REGRESSION_SAVED = "regression_saved"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    ERROR = "error"


class TestRunKind(StrEnum):
    SECURITY_BEFORE = "security_before"
    SECURITY_AFTER = "security_after"
    UTILITY = "utility"
    # Pre-hardening benign baseline; required for the over-refusal delta
    # (docs/adr/0001-report-artifact-pipeline.md "Data prerequisites").
    UTILITY_BEFORE = "utility_before"


class RunPhase(StrEnum):
    """Which pass a run belongs to: original or post-hardening retest."""

    BEFORE = "before"
    AFTER = "after"


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"


class VerdictResolution(StrEnum):
    RULE_CONFIRMED = "rule_confirmed"
    RULE_BLOCKED = "rule_blocked"
    MODEL_CONFIRMED = "model_confirmed"
    MODEL_BLOCKED = "model_blocked"
    DISAGREEMENT = "disagreement"
    NO_EVIDENCE = "no_evidence"
    SEMANTIC_UNAVAILABLE = "semantic_unavailable"
