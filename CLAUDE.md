# RAVEN Coding Instructions

> Canonical copy lives at the repo root so tooling always finds it.
> `docs/CLAUDE.md` is the historical docs-track copy.

## Project context

RAVEN is a bounded, human-supervised security regression system for LLM
applications. The hackathon MVP scans one built-in local ShopHelper bot, runs
a small approved attack suite, judges results with deterministic checks plus
an optional structured LLM judge, proposes hardening, and re-tests security
and benign behavior.

## Monorepo layout

```text
apps/web/        Next.js frontend (scan setup, live progress, findings, report)
apps/api/        FastAPI control plane (scans, findings, policies, reports, SSE)
workers/evaluator/  Evaluation worker (state machine, targets, judges, hardening, regression)
packages/contracts/     Shared JSON/OpenAPI schemas
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
- Report page and JSON/Markdown export.

Defer:

- Arbitrary external HTTP targets.
- SARIF.
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
