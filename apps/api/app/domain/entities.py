"""RAVEN domain entities (Pydantic v2 models).

These models define the typed contracts for API payloads and persisted data.
Model-provider output must be validated into these (or judge-specific) models
before it may enter domain state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.domain.enums import (
    AttackCategory,
    EventKind,
    FindingLabel,
    ScanStatus,
    Severity,
    TestRunKind,
    VerdictResolution,
)
from app.domain.value_objects import Budget, EvidenceRef, TargetRef


def utc_now() -> datetime:
    return datetime.now(UTC)


class ScanConfig(BaseModel):
    """Configuration captured at scan creation (docs/API_CONTRACT.md §2)."""

    target_id: str
    attack_categories: list[AttackCategory] = Field(default_factory=list)
    max_attempts_per_attack: int = Field(default=2, ge=1, le=2)
    enable_mutation: bool = True
    run_benign_suite: bool = True
    regression_only_mode: bool = False
    budget: Budget = Field(default_factory=Budget)


class Scan(BaseModel):
    scan_id: str
    status: ScanStatus = ScanStatus.CREATED
    target: TargetRef
    config: ScanConfig
    progress: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("target")
    @classmethod
    def target_must_be_allowlisted(cls, v: TargetRef) -> TargetRef:
        # Enforced here AND in the application layer; defense in depth.
        from app.security.authorization import assert_target_allowed

        assert_target_allowed(v.target_id)
        return v


class ScanCounts(BaseModel):
    total: int = 0
    confirmed_failures: int = 0
    blocked: int = 0
    needs_review: int = 0
    not_evaluated: int = 0


class SecurityMetrics(BaseModel):
    before_attack_success_rate: float | None = None
    after_attack_success_rate: float | None = None
    benign_success_rate: float | None = None


class ScanView(BaseModel):
    """API view of a scan (docs/API_CONTRACT.md §3)."""

    scan_id: str
    status: ScanStatus
    phase: str = ""
    progress: float = 0.0
    target_id: str
    counts: ScanCounts = Field(default_factory=ScanCounts)
    security_metrics: SecurityMetrics = Field(default_factory=SecurityMetrics)


class AttackCase(BaseModel):
    """Versioned attack case (docs/API_CONTRACT.md §8)."""

    id: str
    category: AttackCategory
    goal: str
    seed_prompt: str
    success_rule: str
    severity: Severity
    references: list[str] = Field(default_factory=list)
    version: str = "v1"


class BenignCase(BaseModel):
    """Normal-use case; expected_behavior is a deterministic marker."""

    id: str
    goal: str
    prompt: str
    expected_behavior: str
    version: str = "v1"


class TranscriptMessage(BaseModel):
    role: str  # system | user | assistant | tool
    content: str
    tool_name: str | None = None
    tool_args_json: str | None = None


class Transcript(BaseModel):
    transcript_id: str
    messages: list[TranscriptMessage] = Field(default_factory=list)


class RuleResult(BaseModel):
    label: FindingLabel
    signals: list[str] = Field(default_factory=list)


class LlmJudgeResult(BaseModel):
    label: FindingLabel
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    model_name: str = ""
    prompt_version: str = ""


class ModelCallRecord(BaseModel):
    call_id: str
    role: str
    model_name: str
    prompt_version: str
    status: str
    duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    created_at: datetime = Field(default_factory=utc_now)


class Verdict(BaseModel):
    """Combined judge output (docs/API_CONTRACT.md §8)."""

    verdict_id: str
    run_id: str
    scan_id: str
    rule_result: RuleResult | None = None
    llm_result: LlmJudgeResult | None = None
    final_label: FindingLabel
    resolution: VerdictResolution
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class Finding(BaseModel):
    finding_id: str
    scan_id: str
    attack_id: str
    category: AttackCategory
    severity: Severity
    label: FindingLabel
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: str
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    needs_review: bool = False
    status: str = "open"  # open | mitigated | reopened
    created_at: datetime = Field(default_factory=utc_now)


class PolicyCandidate(BaseModel):
    """Machine-readable policy compiled from a confirmed finding.

    Example (docs/ARCHITECTURE.md §7):
    {"tool": "issue_refund", "conditions": [...], "high_value_action": ...}
    """

    tool: str
    conditions: list[str] = Field(default_factory=list)
    high_value_action: str = "human_approval_required"
    on_violation: str = "deny_and_log"


class HardeningProposal(BaseModel):
    proposal_id: str
    scan_id: str
    prompt_diff: str
    policy_candidate: PolicyCandidate | None = None
    rationale: str
    affected_cases: list[str] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class Approval(BaseModel):
    approval_id: str
    proposal_id: str
    scan_id: str
    approved: bool
    approved_by: str
    created_at: datetime = Field(default_factory=utc_now)


class TestRun(BaseModel):
    test_run_id: str
    scan_id: str
    kind: TestRunKind
    metrics: dict[str, Any] = Field(default_factory=dict)
    results: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class ScanEvent(BaseModel):
    event_id: int | None = None
    scan_id: str
    kind: EventKind
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class TargetProfile(BaseModel):
    """Recon output. Recon must not attempt aggressive attacks."""

    target_id: str
    version: str
    system_prompt_hash: str
    tools: list[str] = Field(default_factory=list)
    canary_token: str = ""
    notes: list[str] = Field(default_factory=list)


class TargetRequest(BaseModel):
    scan_id: str
    run_id: str
    message: str


class TargetResponse(BaseModel):
    message: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    blocked_by_policy: bool = False
    policy_reason: str | None = None
