"""Typed LangGraph State Model for the RAVEN Security Regression Engine.

Contains all domain state required across the closed-loop scan lifecycle:
initialize -> recon -> plan -> attack -> judge -> resolve -> harden ->
approval interrupt -> retest -> utility -> metrics -> promote -> report.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, TypedDict


class RavenScanState(TypedDict, total=False):
    """Canonical typed state for the RAVEN scan graph."""

    # Core identities and lifecycle
    scan_id: str
    run_id: str
    target_id: str
    target_configuration_hash: str
    phase: str
    status: str

    # Configuration and profiles
    scan_configuration: dict[str, Any]
    target_profile: dict[str, Any] | None

    # Attack planning and execution
    selected_attack_case_ids: list[str]
    attack_results: list[dict[str, Any]]

    # Judging and verdicts
    deterministic_evidence: list[dict[str, Any]]
    semantic_judgments: list[dict[str, Any]]
    resolved_verdicts: list[dict[str, Any]]
    confirmed_findings: list[dict[str, Any]]

    # Hardening and approval
    hardening_proposal: dict[str, Any] | None
    approval_status: str  # "pending", "awaiting_approval", "approved", "rejected", "bypassed"
    approval_metadata: dict[str, Any] | None

    # Retest and utility verification
    security_retest_results: list[dict[str, Any]]
    benign_utility_results: list[dict[str, Any]]

    # Regression and reporting deliverables
    regression_case_ids: list[str]
    report_artifact_ids: list[str]

    # Metrics, budget, and diagnostic telemetry
    budget_used: dict[str, Any]
    metrics: dict[str, Any]
    errors: list[str]
    warnings: list[str]


def compute_target_config_hash(target_id: str, config_dict: dict[str, Any]) -> str:
    """Deterministic hash of target identity and configuration."""
    serialized = json.dumps({"target_id": target_id, "config": config_dict}, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def sanitize_profile_for_state(profile_dict: dict[str, Any] | None) -> dict[str, Any] | None:
    """Redact raw secrets or canary tokens before saving in graph state."""
    if not profile_dict:
        return None
    sanitized = dict(profile_dict)
    if sanitized.get("canary_token"):
        token_len = len(str(sanitized["canary_token"]))
        sanitized["canary_token"] = f"[REDACTED_CANARY_{token_len}_CHARS]"
    return sanitized


def create_initial_state(
    scan_id: str,
    target_id: str = "shophelper-local",
    scan_config: dict[str, Any] | None = None,
) -> RavenScanState:
    """Initialize a fresh, clean graph state."""
    cfg = scan_config or {}
    return {
        "scan_id": scan_id,
        "run_id": f"run_{scan_id}",
        "target_id": target_id,
        "target_configuration_hash": compute_target_config_hash(target_id, cfg),
        "phase": "initialized",
        "status": "created",
        "scan_configuration": cfg,
        "target_profile": None,
        "selected_attack_case_ids": [],
        "attack_results": [],
        "deterministic_evidence": [],
        "semantic_judgments": [],
        "resolved_verdicts": [],
        "confirmed_findings": [],
        "hardening_proposal": None,
        "approval_status": "pending",
        "approval_metadata": None,
        "security_retest_results": [],
        "benign_utility_results": [],
        "regression_case_ids": [],
        "report_artifact_ids": [],
        "budget_used": {
            "attempts": 0,
            "model_calls": 0,
            "tokens": 0,
            "duration_seconds": 0.0,
        },
        "metrics": {},
        "errors": [],
        "warnings": [],
    }
