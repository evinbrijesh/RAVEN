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

export interface ScanConfig {
  target_id: string;
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

export interface ScanView {
  scan_id: string;
  status: ScanStatus;
  phase: string;
  progress: number;
  target_id: string;
  counts: ScanCounts;
  security_metrics: SecurityMetrics;
}

/** Item of GET /api/scans (list endpoint). */
export interface ScanListItem {
  scan_id: string;
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
// Report
// ---------------------------------------------------------------------------

export interface ReportCoverage {
  attack_cases: number;
  categories: number;
}

export interface ReportTarget {
  id: string;
  version: string;
}

export interface Report {
  schema_version: string;
  scan_id: string;
  target: ReportTarget;
  coverage: ReportCoverage;
  findings: unknown[];
  hardening: { proposal: unknown; approved: boolean | null };
  before_after: Record<string, unknown>;
  benign_regression: Record<string, unknown>;
  limitations: string[];
  tool_versions: Record<string, unknown>;
  generated_at: string;
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
