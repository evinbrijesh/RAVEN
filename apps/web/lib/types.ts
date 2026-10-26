/**
 * Typed contracts mirroring apps/api/app/domain (entities.py, enums.py,
 * value_objects.py) and docs/API_CONTRACT.md. Keep in sync with the API.
 */

export const SCAN_STATUSES = [
  "created",
  "reconning",
  "attacking",
  "judging",
  "hardening_proposed",
  "awaiting_approval",
  "retesting",
  "completed",
  "completed_without_retest",
  "completed_with_limitations",
  "inconclusive",
  "failed_partial",
  "failed_fatal",
] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const FINDING_LABELS = [
  "confirmed_failure",
  "likely_failure",
  "attack_blocked",
  "needs_review",
  "partial_mitigation",
  "regression_detected",
  "not_evaluated",
  "verified_under_stated_checks",
] as const;
export type FindingLabel = (typeof FINDING_LABELS)[number];

export const ATTACK_CATEGORIES = [
  "direct_injection",
  "canary_leakage",
  "sensitive_data",
  "tool_misuse",
] as const;
export type AttackCategory = (typeof ATTACK_CATEGORIES)[number];

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** SSE event kinds emitted by GET /api/scans/{id}/events (EventKind enum). */
export const EVENT_KINDS = [
  "scan_created",
  "phase_changed",
  "recon_completed",
  "attack_started",
  "attack_finished",
  "verdict_created",
  "hardening_proposed",
  "approval_received",
  "retest_started",
  "regression_saved",
  "scan_completed",
  "scan_failed",
  "error",
  // Synthetic terminal marker sent by the API before closing the stream.
  "stream_end",
] as const;
export type EventKind = (typeof EVENT_KINDS)[number];

/** Terminal statuses: the SSE stream closes after these. */
export const TERMINAL_STATUSES: readonly ScanStatus[] = [
  "completed",
  "completed_without_retest",
  "failed_partial",
  "failed_fatal",
];

export function isTerminalStatus(status: ScanStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

export interface Budget {
  max_attack_cases: number;
  max_attempts_per_attack: number;
  max_model_calls: number;
  max_total_tokens: number;
  per_call_timeout_seconds: number;
  scan_timeout_seconds: number;
  concurrency_limit: number;
}

export interface Project {
  project_id: string;
  name: string;
  description?: string;
  created_at?: string;
}

export interface ArtifactVerification {
  artifact_id: string;
  scan_id: string;
  run_id?: string;
  artifact_type: "report" | "transcript";
  format: string;
  valid: boolean;
  tampered: boolean;
  expected_sha256: string;
  computed_sha256: string;
  verified_at: string;
}

export interface ScanConfig {
  target_id: string;
  project_id?: string;
  attack_categories: AttackCategory[];
  max_attempts_per_attack: number;
  enable_mutation: boolean;
  run_benign_suite: boolean;
  regression_only_mode?: boolean;
  budget: Budget;
}

export interface ScanCounts {
  total: number;
  confirmed_failures: number;
  blocked: number;
  needs_review: number;
  not_evaluated: number;
}

export interface SecurityMetrics {
  before_attack_success_rate: number | null;
  after_attack_success_rate: number | null;
  benign_success_rate: number | null;
}

export interface TargetProfile {
  target_id: string;
  version: string;
  system_prompt_hash: string;
  tools: string[];
  canary_token: string;
  notes: string[];
}

export interface ScanView {
  scan_id: string;
  project_id?: string;
  status: ScanStatus;
  phase: string;
  progress: number;
  target_id: string;
  counts: ScanCounts;
  security_metrics: SecurityMetrics;
  profile?: TargetProfile | null;
}

/** Item of GET /api/scans (list endpoint). */
export interface ScanListItem {
  scan_id: string;
  project_id?: string;
  status: ScanStatus;
  target_id: string;
}

export interface CreateScanResponse {
  scan_id: string;
  status: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface Finding {
  finding_id: string;
  scan_id: string;
  attack_id: string;
  category: AttackCategory;
  severity: Severity;
  label: FindingLabel;
  confidence: number;
  summary: string;
  evidence_refs: string[];
  needs_review: boolean;
  status: string;
  created_at: string;
}

export interface FindingsResponse {
  items: Finding[];
}

// ---------------------------------------------------------------------------
// Hardening proposal + approval
// ---------------------------------------------------------------------------

export interface PolicyCandidate {
  tool: string;
  conditions: string[];
  high_value_action: string;
  on_violation: string;
}

export interface HardeningProposal {
  proposal_id: string;
  scan_id: string;
  prompt_diff: string;
  policy_diff?: string;
  policy_candidate: PolicyCandidate | null;
  rationale: string;
  affected_cases: string[];
  risks: string[];
  created_at: string;
}

export interface Approval {
  approval_id: string;
  proposal_id: string;
  scan_id: string;
  approved: boolean;
  approved_by: string;
  created_at: string;
}

export interface ApproveHardeningResponse {
  scan_id: string;
  status: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Report (canonical wire contract v1.0 — packages/contracts/report.schema.json)
// ---------------------------------------------------------------------------

export const REPORT_VERDICTS = [
  "improved",
  "confirmed_vulnerable",
  "no_confirmed_findings",
  "inconclusive",
  "partial",
] as const;
export type ReportVerdict = (typeof REPORT_VERDICTS)[number];

export interface ReportGenerator {
  name: "raven";
  version: string;
}

export interface ReportTarget {
  id: string;
  version: string;
}

export interface ReportProfile {
  tools: string[];
  canary_present: boolean;
  system_prompt_hash: string;
  notes: string[];
}

export interface ReportScan {
  scan_id: string;
  status: ScanStatus;
  created_at: string;
  completed_at: string | null;
  target: ReportTarget;
  config: ScanConfig;
  profile: ReportProfile | null;
}

export interface ReportCounts {
  attack_cases: number;
  evaluated: number;
  not_evaluated: number;
  confirmed_failure: number;
  likely_failure: number;
  attack_blocked: number;
  needs_review: number;
  benign_cases: number;
  benign_passed: number;
  regressions: number;
}

export interface ReportJudgeInfo {
  deterministic_available: boolean;
  semantic_available: boolean;
  disagreements: number;
  model_name: string | null;
  prompt_version: string | null;
}

export interface ReportSummary {
  verdict: ReportVerdict;
  headline: string;
  counts: ReportCounts;
  judge: ReportJudgeInfo;
}

export interface ReportCoverage {
  attack_cases: number;
  categories: AttackCategory[];
  benign_cases: number;
  attack_catalog_version: string;
  benign_catalog_version: string;
}

export interface ReportAttackMeta {
  goal: string;
  success_rule: string;
  seed_prompt_redacted: string;
  references: string[];
  version: string;
}

export interface ReportDeterministic {
  label: FindingLabel | null;
  signals: string[];
}

export interface ReportSemantic {
  label: FindingLabel | null;
  confidence: number | null;
  reason: string | null;
  model_name: string | null;
  prompt_version: string | null;
  available: boolean;
}

export interface ReportRunRef {
  run_id: string;
  attempt: number;
  phase: "before" | "after";
  status: string;
}

export interface ReportEvidenceRef {
  ref_id: string;
  kind: string;
  description: string;
}

export interface ReportTranscriptMessage {
  role: string;
  content: string;
  tool_name?: string | null;
  tool_args_json?: string | null;
}

export interface ReportTranscript {
  transcript_id: string;
  messages: ReportTranscriptMessage[];
  truncated: boolean;
}

export type ReportEvidenceKind =
  | "run"
  | "transcript"
  | "rule_check"
  | "model_call"
  | "approval"
  | "test_run";

export interface ReportEvidence {
  ref_id: string;
  kind: ReportEvidenceKind;
  description: string;
  run_id?: string | null;
  attempt?: number | null;
  phase?: "before" | "after" | null;
  transcript?: ReportTranscript | null;
}

export interface ReportPolicyCandidate {
  tool: string;
  conditions: string[];
  high_value_action: string;
  on_violation: string;
}

export interface ReportProposal {
  proposal_id: string;
  scan_id: string;
  prompt_diff: string;
  policy_candidate: ReportPolicyCandidate | null;
  rationale: string;
  affected_cases: string[];
  risks: string[];
  created_at: string;
}

export interface ReportApproval {
  approved: boolean;
  approved_by: string;
  created_at: string;
}

export interface ReportHardening {
  proposal: ReportProposal | null;
  approval: ReportApproval | null;
  applied_to: "temporary_target" | "not_applied";
}

export interface CategoryMetric {
  category: AttackCategory;
  before_success_rate: number | null;
  after_success_rate: number | null;
  delta: number | null;
}

export interface ReportSecurityMetrics {
  before_attack_success_rate: number | null;
  after_attack_success_rate: number | null;
  delta: number | null;
  before_blocked_rate: number | null;
  after_blocked_rate: number | null;
  per_category: CategoryMetric[];
}

export interface ReportUtilityCase {
  case_id: string;
  goal: string;
  prompt_redacted: string;
  expected: string;
  passed_before: boolean | null;
  passed_after: boolean | null;
  over_refusal: boolean;
}

export interface ReportUtilityMetrics {
  before_benign_success_rate: number | null;
  after_benign_success_rate: number | null;
  delta: number | null;
  cases: ReportUtilityCase[];
  over_refusal_case_ids: string[];
}

export interface ReportBeforeAfter {
  security: ReportSecurityMetrics;
  utility: ReportUtilityMetrics;
}

export interface ReportModelUsage {
  semantic_judge_available: boolean;
  model_name: string | null;
  prompt_version: string | null;
  calls: number;
  input_tokens: number | null;
  output_tokens: number | null;
  duration_ms: number | null;
}

export interface ReportRedaction {
  applied: boolean;
  transcript_excerpt_chars: number;
  redacted_fields: string[];
}

export interface ReportIntegrity {
  content_sha256: string;
  source: "persisted_evidence_only";
}

export interface ReportFinding {
  finding_id: string;
  attack_id: string;
  category: AttackCategory;
  severity: Severity;
  label: FindingLabel;
  confidence: number;
  needs_review: boolean;
  summary: string;
  attack: ReportAttackMeta | null;
  deterministic: ReportDeterministic | null;
  semantic: ReportSemantic;
  resolution: string | null;
  evidence_refs: ReportEvidenceRef[];
  run: ReportRunRef | null;
  evidence_complete: boolean;
}

export interface Report {
  schema_version: "1.0";
  report_id: string;
  generated_at: string;
  generator: ReportGenerator;
  scan: ReportScan;
  summary: ReportSummary;
  coverage: ReportCoverage;
  findings: ReportFinding[];
  hardening: ReportHardening;
  before_after: ReportBeforeAfter;
  evidence: ReportEvidence[];
  model_usage: ReportModelUsage;
  tool_versions: Record<string, string>;
  redaction: ReportRedaction;
  limitations: string[];
  integrity: ReportIntegrity;
}

// ---------------------------------------------------------------------------
// SSE events
// ---------------------------------------------------------------------------

export interface ScanEvent {
  kind: EventKind;
  /** Raw payload fields; shape varies per event kind. */
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// API error format (docs/API_CONTRACT.md §9)
// ---------------------------------------------------------------------------

export interface ApiError {
  code: string;
  message: string;
  retryable?: boolean;
  scan_status?: string;
}

// ---------------------------------------------------------------------------
// Regression Suite types
// ---------------------------------------------------------------------------

export interface RegressionCase {
  regression_id: string;
  target_id: string;
  attack_case_id: string;
  active: boolean;
  created_at: string;
  case: {
    id: string;
    category?: string;
    goal?: string;
    seed_prompt?: string;
    severity?: string;
    references?: string[];
    success_rule?: string;
  };
}

export interface RegressionsResponse {
  target_id: string;
  total: number;
  active_count: number;
  items: RegressionCase[];
}

