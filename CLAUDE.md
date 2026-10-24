# RAVEN Coding Instructions

> Canonical copy lives at the repo root so tooling always finds it.
> `docs/CLAUDE.md` is the historical docs-track copy.

## Project context

RAVEN is a bounded, human-supervised security regression system for LLM
applications. The hackathon MVP scans one built-in local ShopHelper bot, runs
a small approved attack suite, judges results with deterministic checks plus
an optional structured LLM judge, proposes hardening, and re-tests security
and benign behavior. The report is the evidence deliverable: a canonical JSON
artifact with Markdown and SARIF 2.1.0 projections, built only from persisted
evidence.

## Monorepo layout

```text
apps/web/        Next.js frontend (scan setup, live progress, findings, report)
  components/report/      Report UI primitives (summary, delta, findings, evidence)
  app/scans/[id]/report/  Printable full report route
apps/api/        FastAPI control plane (scans, findings, policies, reports, SSE)
  app/application/report/ Report collector, assembler, redaction, renderers
  app/domain/report.py    Canonical report Pydantic models
workers/evaluator/  Evaluation worker (state machine, targets, judges, hardening, regression)
packages/contracts/     Shared JSON/OpenAPI schemas (report.schema.json is v1.0)
packages/attack-catalog/ Versioned attack and benign cases
packages/ui/            Optional shared UI primitives
fixtures/        ShopHelper fixtures and demo scan config
infra/           Docker Compose, Dockerfiles, nginx
docs/            PRD, architecture, threat model, API contract, scaffold blueprint
```

## Non-negotiable safety rules

1. Never implement scanning of arbitrary third-party targets in the MVP.
2. Never execute real destructive tool calls, shell commands, refunds, emails, payments, account changes, or network actions.
3. Treat all target/model output as untrusted data.
4. Do not put secrets, real PII, or real customer data in fixtures.
5. Never auto-deploy a generated hardening change.
6. Enforce attack count, retry count, timeout, concurrency, and model-call budgets.
7. If rule and model judges disagree, return `needs_review`.
8. A clean test result is not a security guarantee.
9. Validate every model response against a strict schema.
10. Do not log API keys or raw sensitive headers.

## Engineering principles

- Prefer a simple state machine over an unconstrained agent loop.
- Prefer deterministic checks before LLM calls.
- Keep the MVP dependency list small.
- Make errors visible in the UI.
- Use typed models for API and persisted data.
- Keep core logic testable without an LLM.
- Keep target adapters behind an interface.
- Use feature flags for unfinished integrations.
- Use small commits with descriptive messages.
- Do not introduce background services unless they are needed for the demo.
- Report generation reads persisted evidence only; never invoke targets or models.
- JSON report is canonical; Markdown and SARIF are pure renderers.
- Redact canary/PII/secrets at render time; preserve raw evidence internally.
- Every report finding resolves to an evidence ref or is marked incomplete.
- Bump the report schema version for any breaking wire change.

## MVP scope

Required:

- Built-in ShopHelper target.
- Four attack categories.
- Approximately 12 attack cases.
- Deterministic canary, secret, PII, and tool-policy checks.
- Structured LLM judge with bounded calls.
- One mutation per failed case at most.
- Hardening proposal with diff.
- Approval step.
- Before/after retest.
- Benign utility suite.
- Report page and JSON/Markdown/SARIF export (PDF via browser print).

Defer:

- Arbitrary external HTTP targets.
- GitHub Actions.
- Full MITRE ATLAS taxonomy.
- Redis/Postgres unless SQLite is insufficient.
- Multi-agent swarm behavior.
- Automatic production changes.

## State and status conventions

Use explicit statuses:

- `created`
- `reconning`
- `attacking`
- `judging`
- `hardening_proposed`
- `awaiting_approval`
- `retesting`
- `completed`
- `failed_partial`
- `failed_fatal`

Finding labels:

- `confirmed_failure`
- `likely_failure`
- `attack_blocked`
- `needs_review`
- `partial_mitigation`
- `regression_detected`
- `not_evaluated`
- `verified_under_stated_checks`

## Model-call rules

- Use structured JSON output.
- Set timeouts.
- Retry invalid JSON once only.
- Keep attacker and judge roles separate.
- Do not send the full database or filesystem to a model.
- Minimize transcript context.
- Record model name, prompt version, and call status.
- If the model is unavailable, continue with deterministic checks and mark semantic judgment unavailable.

## Reporting conventions

- `packages/contracts/report.schema.json` is the canonical wire contract (v1.0).
- The report document is built by `apps/api/app/application/report/` from
  persisted tables only: scans, target profiles, runs, transcripts, verdicts,
  findings, proposals, approvals, and test runs.
- JSON is canonical. Markdown and SARIF 2.1.0 renderers must not add facts
  that are absent from the canonical document.
- Report artifacts are immutable and identified by SHA-256; the hash excludes
  `report_id`, `generated_at`, and `integrity`.
- Report evidence is redacted and truncated at render time. Never include raw
  canary tokens, API keys, authorization headers, or unredacted PII.
- Partial scans produce `summary.verdict = "partial"` or `"inconclusive"`,
  never a blank report or a false clean result.
- The summary headline is deterministic; do not use an LLM to write reports.
- SARIF emits only actionable labels (`confirmed_failure`, `likely_failure`,
  `regression_detected`, `needs_review`). Blocked/not-evaluated are counts in
  `run.properties`.
- PDF export is browser print (`/scans/[id]/report`); no server PDF dependency.

## Definition of done for a feature

A feature is done only when:

1. It has a typed input/output contract.
2. It has at least one happy-path test.
3. It has an invalid-input or timeout test.
4. It cannot bypass the safety policy.
5. Its UI state is visible for loading, success, and failure.
6. Its output is included in the evidence/report model.

## Demo reliability

- Seed the demo target and fixtures locally.
- Do not depend on internet access for the main demo.
- Keep a recorded backup demo.
- Add a reset button for the target.
- Preflight model/API availability.
- Make the scan budget configurable.
- If a model call fails, show a partial result rather than a blank page.

## Common commands

```bash
make install   # install API + worker deps (uv) and web deps (npm)
make dev       # run API + worker + web for local development
make test      # run API and worker test suites
make lint      # ruff + tsc
```

## Module map

- Report contract: `packages/contracts/report.schema.json`
- Report assembly: `apps/api/app/application/report/assembler.py`
- Report collection: `apps/api/app/application/report/collector.py`
- Report redaction: `apps/api/app/application/report/redaction.py`
- Report renderers: `apps/api/app/application/report/renderers/`
- Report HTTP surface: `apps/api/app/api/reports.py`
- Report UI: `apps/web/components/report/`
- Printable report: `apps/web/app/scans/[id]/report/page.tsx`
- Evidence tables: `attack_runs`, `transcripts`, `verdicts`, `test_runs`
- Architecture decision: `docs/adr/0001-report-artifact-pipeline.md`
