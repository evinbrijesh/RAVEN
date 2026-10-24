# ADR 0001 — Report artifact pipeline

- Status: Accepted
- Date: 2026-10-25
- Owners: Architect
- Related: PRD §8 FR-11, §13 P1/P2, §15; DATA_FLOW §9; API_CONTRACT §7

## Context

The MVP already has a report endpoint (`GET /api/scans/{scan_id}/report`) and a
small report UI, but the artifact is not sufficient for FR-11 or for the product
claim in PRD §15:

- It reports findings summary only — no target profile, no attack-case
  metadata, no evidence transcripts, no rule-vs-LLM detail.
- `coverage` is derived from `findings`, so blocked attacks are undercounted.
- Metrics are three scalars; there is no per-category or utility/over-refusal
  view, and no pre-hardening benign baseline exists.
- There is no SARIF export, no download disposition, no artifact integrity
  hash, and no redaction ledger.
- The UI renders three facts plus raw JSON.

The report is the evidence deliverable of the product. It must be reproducible,
self-describing, safe to export, and derived only from persisted evidence.

## Decision

1. **The report is an immutable evidence artifact.** JSON is canonical;
   Markdown and SARIF 2.1.0 are pure projections. The same persisted state must
   produce the same artifact body except for `report_id` and `generated_at`.

2. **Report generation never invokes a target, model, shell, or network call.**
   It reads only: `scans`, `target_profiles`, `attack_runs`, `transcripts`,
   `verdicts`, `findings`, `hardening_proposals`, `approvals`, `test_runs`.

3. **Schema version 1.0 replaces 0.1.** The breaking change is accepted because
   the only consumer is `apps/web` and there are no external clients. The
   contract is `packages/contracts/report.schema.json`.

4. **Every finding must resolve to evidence.** A finding with no reachable
   evidence is still emitted, but marked `evidence_complete: false` and called
   out in limitations. Findings are never silently dropped.

5. **Redaction happens at render time.** Raw evidence remains in the database.
   Report output redacts canary tokens, API keys/authorization headers, email,
   phone, and card-like patterns, and truncates transcripts (4,000 chars per
   message, 12,000 chars per evidence bundle).

6. **PDF is browser print.** No server-side PDF dependency is added. The
   printable route is `/scans/[id]/report` with `window.print()`.

7. **Partial reports are allowed.** A non-terminal or failed scan returns
   `200` with `summary.verdict = "partial"` or `"inconclusive"`, never a blank
   page or a false clean result.

8. **Artifacts are persisted with a SHA-256 hash.** `report_artifacts` gains
   `schema_version`, `content_sha256`, and `generator_version`. The hash covers
   the canonical body excluding `report_id`, `generated_at`, and `integrity`.

## Pipeline

```text
persisted tables
      │
      ▼
collector.py ──► ReportEvidenceBundle (runs, verdicts, transcripts, test runs,
      │                                  profile, proposal, approval, events)
      ▼
assembler.py ──► ReportDocument (summary, coverage, findings, before/after,
      │                           utility, evidence, model usage, versions)
      ▼
redaction.py ──► redacted canonical document
      │
      ├──► renderers/json.py      canonical JSON
      ├──► renderers/markdown.py  human-readable
      ├──► renderers/sarif.py     SARIF 2.1.0
      └──► service.py             hash + persist artifact
```

Module ownership:

```text
apps/api/app/domain/report.py                 Pydantic models (wire truth)
apps/api/app/application/report/collector.py  DB reads only
apps/api/app/application/report/assembler.py  deterministic assembly + verdict
apps/api/app/application/report/redaction.py  redaction/truncation
apps/api/app/application/report/service.py    orchestration + artifact cache
apps/api/app/application/report/renderers/    json/markdown/sarif
apps/api/app/api/reports.py                   HTTP surface
apps/web/components/report/                   UI
apps/web/app/scans/[id]/report/page.tsx       printable full report
```

## API contract

```http
GET /api/scans/{scan_id}/report?format=json|markdown|sarif&download=false
```

| Condition | Result |
|---|---|
| `format=json` | `200 application/json` |
| `format=markdown` | `200 text/markdown; charset=utf-8` |
| `format=sarif` | `200 application/sarif+json` |
| unknown format | `400 VALIDATION_FAILED` |
| unknown scan | `404 NOT_FOUND` |
| partial/failed scan | `200` with `summary.verdict` set accordingly |
| `download=true` | `Content-Disposition: attachment; filename="raven-{scan_id}-report.{ext}"` |

Response headers:

```http
X-RAVEN-Report-Schema: 1.0
X-RAVEN-Report-SHA256: <64 hex>
X-RAVEN-Report-Artifact: <rpt_...>
```

## Verdict rules

Deterministic, evaluated in order:

1. `partial` — terminal status is `failed_partial`/`failed_fatal`, or no
   `SECURITY_BEFORE` run exists.
2. `inconclusive` — `needs_review > 0` while the semantic judge is unavailable,
   or a `completed_without_retest` scan has no after run.
3. `confirmed_vulnerable` — `after_attack_success_rate > 0`, or no retest while
   confirmed/likely findings exist.
4. `improved` — `before > 0`, `after < before`, and utility delta is not below
   `-0.10`.
5. `no_confirmed_findings` — all selected attack cases evaluated and zero
   confirmed/likely/regression findings.

`utility_regressed` is true when `benign_after - benign_before < -0.10` or any
benign case passed before and fails after. The headline is a deterministic
template; no model is involved.

## Data prerequisites

These are required from the worker before the report can be complete:

1. `test_runs.results` entries must carry case metadata:
   - security: `attack_id`, `category`, `goal`, `success_rule`, `references`,
     `attack_version`, `severity`, `label`, `resolution`, `signals`.
   - utility: `case_id`, `goal`, `prompt`, `expected`, `passed`,
     `blocked_by_policy`, `version`.
2. A pre-hardening benign baseline must exist as `TestRunKind.UTILITY_BEFORE`
   with metrics `{benign_success_rate, cases}`.
3. The semantic judge must be wired into `SecurityRegressionRunner` and its
   `LlmJudgeResult` persisted on the verdict. If unavailable, the report marks
   `semantic_judge_available: false`; it never guesses.
4. `RunRepository` needs a typed transcript accessor (`get_transcript(run_id)`)
   and `TestRunRepository.latest_for_scan(scan_id, kind)`.
5. Token usage is optional. If not persisted, report `null` and add a
   limitation rather than inventing numbers.

## SARIF mapping

| Category | `ruleId` | OWASP |
|---|---|---|
| `direct_injection` | `RAVEN/LLM01-prompt-injection` | LLM01 |
| `canary_leakage` | `RAVEN/LLM07-system-prompt-leakage` | LLM07 |
| `sensitive_data` | `RAVEN/LLM06-sensitive-information-disclosure` | LLM06 |
| `tool_misuse` | `RAVEN/LLM08-excessive-agency` | LLM08 |

Only actionable labels become SARIF results: `confirmed_failure`,
`likely_failure`, `regression_detected`, `needs_review`. `attack_blocked` and
`not_evaluated` are counted in `run.properties`, not emitted as results.

- `level`: critical/high → `error`, medium → `warning`, low/needs_review → `note`
- `partialFingerprints.ravenFindingV1`:
  `sha256(target_id:attack_id:category:success_rule)` — stable across scans.
- `locations[0].physicalLocation.artifactLocation.uri`:
  `raven://target/{target_id}/attack/{attack_id}`
- `automationDetails.id`: `raven/{target_id}`
- No absolute paths, secrets, or canary values.

## UI contract

- `ReportSummary` — verdict, headline, target, scan status, partial/semantic
  badges.
- `SecurityUtilityDelta` — attack success rate before → after with delta in
  percentage points; benign pass rate before → after; over-refusal cases.
- `ReportFindings` — table plus expandable evidence (deterministic signals,
  semantic reason/confidence, redacted transcript, resolution).
- `ReportHardening` — read-only diff, rationale, risks, approval record.
- `ReportLimitations` — limitations, redaction note, schema version, SHA-256.
- `ReportActions` — download JSON/Markdown/SARIF; print to PDF.
- States: loading, error/retry, partial, empty findings, semantic unavailable,
  baseline not measured.

## Consequences

Positive:

- FR-11 becomes fully covered and the report becomes the product's evidence
  deliverable.
- SARIF enables GitHub Code Scanning and CI consumers without redesign.
- Deterministic assembly is testable without an LLM.
- Redaction and hash give export safety and provenance.

Costs / risks:

- Schema v1.0 is a breaking change; web types must be updated in the same
  change.
- Worker enrichment and the benign baseline are prerequisites; a report on an
  old scan must degrade to `inconclusive` rather than fail.
- Browser print quality depends on print CSS; server PDF is deliberately
  deferred.
- Transcript evidence can be sensitive; exports are always redacted.

## Out of scope / follow-up ADRs

- Persistent regression suite ("findings become tests").
- Authorized HTTP target adapter with consent and SSRF controls.
- Judge-disagreement inspector beyond the report row.
- SARIF upload action / GitHub App integration.
- Server-side PDF generation.

## Implementation status (2026-10-25)

The contract (v1.0) and this ADR are the target. Work in progress in the
workspace does not yet satisfy them:

| Area | Current state | Required before merge |
|---|---|---|
| Wire version | `generate_report.py` still emits `0.1` | Replace with `ReportDocument` v1.0; web types in the same change |
| Report pipeline | Single `generate_report.py`; no collector/assembler/renderer split | Create `application/report/` package per pipeline above |
| SARIF | `report_to_sarif()` in `generate_report.py`; per-attack rules, no fingerprints, no `run.properties` | Move to `renderers/sarif.py`; use category rules, stable fingerprints, redaction |
| Evidence | No transcripts/profile/verdicts in report | Collector must read `attack_runs`, `transcripts`, `verdicts`, `target_profiles` |
| Utility baseline | Only after-hardening run exists | Add `UTILITY_BEFORE` and record it before hardening |
| Worker metadata | `test_runs.results` lacks category/goal/references/prompt | Enrich security and utility result entries |
| Artifact integrity | No hash, duplicates on every request | `report_artifacts` hash + idempotent write |
| Regression promotion | `POST /findings/{id}/promote-regression` saves a stub finding JSON | Persist the real catalog `AttackCase`; validate label; dedupe |
| SSRF helper | `security/ssrf.py` validates URL but not redirects/rebinding | HTTP adapter must re-check on every hop and pin resolution |
| Regression-only mode | Selected from the first `max_attack_cases` slice before filtering | Select full catalog, filter active regressions, then cap |

Implementation is owned by Engineer. The contract must not change without a
new ADR.

## Review gate (2026-10-25)

The current working tree is **not mergeable**. Blockers from the architecture
review:

1. **B1 — Contract mismatch.** API still emits v0.1; none of the required v1.0
   sections exist. `report.schema.json` validation fails.
2. **B2 — Canary leak.** `prompt_diff` in the persisted JSON report contains
   the fixture canary; no report-time redaction or truncation exists.
3. **B3 — No artifact integrity.** No `report_id`, SHA-256, hash columns,
   idempotent write, download headers, or content-type handling.
4. **B4 — SARIF non-compliance.** Per-attack rules, no fingerprints, no
   actionable filter, fake location, no run properties/invocations, no
   redaction, wrong media type.
5. **B5 — Regression promotion unsafe.** Cross-scan finding lookup, no label
   validation, stub `AttackCase`, wrong `case_json`, no dedupe, no audit.
6. **B6 — Regression-only mode false clean.** Budget slice applied before
   filtering; empty selection can complete clean; fallback runs arbitrary
   attacks; retest ignores the mode.
7. **B7 — Missing persistence prerequisites.** No `UTILITY_BEFORE`, no
   `completed_at`, no transcript/latest test-run accessors, worker result rows
   lack case metadata, model-call records are not persisted.
8. **B8 — SSRF helper unsafe to integrate.** No redirect/DNS-rebinding
   protection, incomplete range checks, dev bypass unguarded, consent helper
   unused.

Minimum merge gate: B1–B8 closed, v1.0 schema validation test green, redaction
tests green, SARIF structural tests green, regression/SSRF failure-path tests
green, and `make test` + `make lint` pass.
