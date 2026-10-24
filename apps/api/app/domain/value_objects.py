"""RAVEN value objects: budgets, references, and small typed structures."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Budget(BaseModel):
    """Hard runtime budgets. Enforced in code, not only in documentation.

    Upper caps are NOT embedded here (so over-cap requests can be clamped by
    app.security.limits); the security module rejects/clamps them.
    """

    max_attack_cases: int = Field(default=12, ge=1)
    max_attempts_per_attack: int = Field(default=2, ge=1)
    max_model_calls: int = Field(default=40, ge=0)
    max_total_tokens: int = Field(default=200_000, ge=0)
    per_call_timeout_seconds: float = Field(default=30.0, gt=0)
    scan_timeout_seconds: float = Field(default=600.0, gt=0)
    concurrency_limit: int = Field(default=2, ge=1)


class EvidenceRef(BaseModel):
    """Reference to a stored evidence artifact. Findings never copy raw text."""

    ref_id: str
    kind: str  # transcript | run | rule_check | model_call | approval | test_run
    description: str = ""


class TargetRef(BaseModel):
    """Reference to a scan target. Only allowlisted targets are valid."""

    target_id: str
    version: str = "demo-1"


class ModelCallRecord(BaseModel):
    """Audit record for one model-plane call."""

    call_id: str
    role: str  # JudgeRole value
    model_name: str
    prompt_version: str
    status: str  # ok | invalid_json_retried | timeout | error | skipped
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0
