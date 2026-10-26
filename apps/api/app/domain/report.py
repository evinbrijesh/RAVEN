"""Canonical report document models (wire contract v1.0).

Mirrors packages/contracts/report.schema.json — the JSON Schema is the
language-neutral reference; these Pydantic models are authoritative for
runtime validation (packages/contracts/README.md). Any breaking change here
requires a schema version bump and a new ADR.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import (
    AttackCategory,
    FindingLabel,
    ScanStatus,
    Severity,
    VerdictResolution,
)

_FORBID = ConfigDict(extra="forbid")


class ReportVerdict(StrEnum):
    IMPROVED = "improved"
    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    NO_CONFIRMED_FINDINGS = "no_confirmed_findings"
    INCONCLUSIVE = "inconclusive"
    PARTIAL = "partial"


class GeneratorInfo(BaseModel):
    model_config = _FORBID
    name: Literal["raven"] = "raven"
    version: str


class ReportTarget(BaseModel):
    model_config = _FORBID
    id: str
    version: str


class ReportBudget(BaseModel):
    model_config = _FORBID
    max_attack_cases: int
    max_attempts_per_attack: int
    max_model_calls: int
    max_total_tokens: int
    per_call_timeout_seconds: float
    scan_timeout_seconds: float
    concurrency_limit: int


class ReportScanConfig(BaseModel):
    model_config = _FORBID
    target_id: str
    attack_categories: list[AttackCategory]
    max_attempts_per_attack: int
    enable_mutation: bool
    run_benign_suite: bool
    regression_only_mode: bool = False
    budget: ReportBudget



class ReportProfile(BaseModel):
    """Recon profile for the report. Never carries the raw canary token."""

    model_config = _FORBID
    tools: list[str]
    canary_present: bool
    system_prompt_hash: str
    notes: list[str]


class ReportScan(BaseModel):
    model_config = _FORBID
    scan_id: str
    status: ScanStatus
    created_at: datetime
    completed_at: datetime | None
    target: ReportTarget
    config: ReportScanConfig
    profile: ReportProfile | None


class ReportCounts(BaseModel):
    model_config = _FORBID
    attack_cases: int
    evaluated: int
    not_evaluated: int
    confirmed_failure: int
    likely_failure: int
    attack_blocked: int
    needs_review: int
    benign_cases: int
    benign_passed: int
    regressions: int


class ReportJudgeInfo(BaseModel):
    model_config = _FORBID
    deterministic_available: bool
    semantic_available: bool
    disagreements: int
    model_name: str | None
    prompt_version: str | None


class ReportSummary(BaseModel):
    model_config = _FORBID
    verdict: ReportVerdict
    headline: str
    counts: ReportCounts
    judge: ReportJudgeInfo


class ReportCoverage(BaseModel):
    model_config = _FORBID
    attack_cases: int
    categories: list[AttackCategory]
    benign_cases: int
    attack_catalog_version: str
    benign_catalog_version: str


class ReportAttackMeta(BaseModel):
    model_config = _FORBID
    goal: str
    success_rule: str
    seed_prompt_redacted: str
    references: list[str]
    version: str


class ReportDeterministic(BaseModel):
    model_config = _FORBID
    label: FindingLabel | None
    signals: list[str]


class ReportSemantic(BaseModel):
    model_config = _FORBID
    label: FindingLabel | None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reason: str | None
    model_name: str | None
    prompt_version: str | None
    available: bool


class ReportRunRef(BaseModel):
    model_config = _FORBID
    run_id: str
    attempt: int
    phase: Literal["before", "after"]
    status: str


class ReportEvidenceRef(BaseModel):
    model_config = _FORBID
    ref_id: str
    kind: str
    description: str = ""


class ReportTranscriptMessage(BaseModel):
    model_config = _FORBID
    role: str
    content: str
    tool_name: str | None = None
    tool_args_json: str | None = None


class ReportTranscript(BaseModel):
    model_config = _FORBID
    transcript_id: str
    messages: list[ReportTranscriptMessage]
    truncated: bool


class ReportEvidence(BaseModel):
    model_config = _FORBID
    ref_id: str
    kind: Literal["run", "transcript", "rule_check", "model_call", "approval", "test_run"]
    description: str
    run_id: str | None = None
    attempt: int | None = None
    phase: Literal["before", "after"] | None = None
    transcript: ReportTranscript | None = None


class ReportPolicyCandidate(BaseModel):
    model_config = _FORBID
    tool: str
    conditions: list[str]
    high_value_action: str
    on_violation: str


class ReportProposal(BaseModel):
    model_config = _FORBID
    proposal_id: str
    scan_id: str
    prompt_diff: str
    policy_candidate: ReportPolicyCandidate | None
    rationale: str
    affected_cases: list[str]
    risks: list[str]
    created_at: datetime


class ReportApproval(BaseModel):
    model_config = _FORBID
    approved: bool
    approved_by: str
    created_at: datetime


class ReportHardening(BaseModel):
    model_config = _FORBID
    proposal: ReportProposal | None
    approval: ReportApproval | None
    applied_to: Literal["temporary_target", "not_applied"]


class CategoryMetric(BaseModel):
    model_config = _FORBID
    category: AttackCategory
    before_success_rate: float | None
    after_success_rate: float | None
    delta: float | None


class ReportSecurityMetrics(BaseModel):
    model_config = _FORBID
    before_attack_success_rate: float | None
    after_attack_success_rate: float | None
    delta: float | None
    before_blocked_rate: float | None
    after_blocked_rate: float | None
    per_category: list[CategoryMetric]


class ReportUtilityCase(BaseModel):
    model_config = _FORBID
    case_id: str
    goal: str
    prompt_redacted: str
    expected: str
    passed_before: bool | None
    passed_after: bool | None
    over_refusal: bool


class ReportUtilityMetrics(BaseModel):
    model_config = _FORBID
    before_benign_success_rate: float | None
    after_benign_success_rate: float | None
    delta: float | None
    cases: list[ReportUtilityCase]
    over_refusal_case_ids: list[str]


class ReportBeforeAfter(BaseModel):
    model_config = _FORBID
    security: ReportSecurityMetrics
    utility: ReportUtilityMetrics


class ReportModelUsage(BaseModel):
    model_config = _FORBID
    semantic_judge_available: bool
    model_name: str | None
    prompt_version: str | None
    calls: int
    input_tokens: int | None
    output_tokens: int | None
    duration_ms: int | None


class ReportRedaction(BaseModel):
    model_config = _FORBID
    applied: bool
    transcript_excerpt_chars: int
    redacted_fields: list[str]


class ReportIntegrity(BaseModel):
    model_config = _FORBID
    content_sha256: str
    source: Literal["persisted_evidence_only"] = "persisted_evidence_only"


class ReportFinding(BaseModel):
    model_config = _FORBID
    finding_id: str
    attack_id: str
    category: AttackCategory
    severity: Severity
    label: FindingLabel
    confidence: float = Field(ge=0.0, le=1.0)
    needs_review: bool
    summary: str
    attack: ReportAttackMeta | None
    deterministic: ReportDeterministic | None
    semantic: ReportSemantic
    resolution: VerdictResolution | None
    evidence_refs: list[ReportEvidenceRef]
    run: ReportRunRef | None
    evidence_complete: bool


class ReportDocument(BaseModel):
    """Canonical report artifact (packages/contracts/report.schema.json v1.0)."""

    model_config = _FORBID
    schema_version: Literal["1.0"] = "1.0"
    report_id: str = Field(pattern=r"^rpt_[A-Za-z0-9]+$")
    generated_at: datetime
    generator: GeneratorInfo
    scan: ReportScan
    summary: ReportSummary
    coverage: ReportCoverage
    findings: list[ReportFinding]
    hardening: ReportHardening
    before_after: ReportBeforeAfter
    evidence: list[ReportEvidence]
    model_usage: ReportModelUsage
    tool_versions: dict[str, str]
    redaction: ReportRedaction
    limitations: list[str] = Field(min_length=1)
    integrity: ReportIntegrity
