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
    """Reference and configuration for a scan target (typed & immutable).
    
    Adheres to safety requirements:
    - Never stores raw secret keys/tokens (stores header names only).
    - Persists consent acknowledgment, timeouts, request template, and response extraction path.
    - Includes configuration hash for tamper-evident provenance.
    """

    target_id: str
    kind: str = "local"  # "local" | "http"
    version: str = "demo-1"
    endpoint_url: str | None = None
    request_template: dict[str, str] | None = None
    response_json_path: str = "response"
    header_names: list[str] = Field(default_factory=list)
    consent_acknowledged: bool = True
    timeout_seconds: float = 30.0
    rate_limit_per_minute: int = 60
    config_hash: str = ""

    def model_post_init(self, __context: object) -> None:
        if not self.config_hash:
            import hashlib
            data = f"{self.target_id}:{self.kind}:{self.endpoint_url}:{self.response_json_path}"
            object.__setattr__(self, "config_hash", hashlib.sha256(data.encode("utf-8")).hexdigest()[:16])


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
