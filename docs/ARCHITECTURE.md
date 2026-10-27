# RAVEN Architecture

## 1. Architecture principles

1. Deterministic checks before probabilistic checks.
2. Every conclusion must link to evidence.
3. The LLM is an untrusted component, not the policy authority.
4. The attack loop is bounded by time, cost, count, and concurrency.
5. Hardening is proposed and tested before it is accepted.
6. Security improvement and normal-use utility are separate metrics.
7. A clean result means clean under stated checks, not globally secure.

## 2. MVP components

### Frontend

- Next.js or a simple React interface.
- Scan configuration form.
- Live progress feed over SSE.
- Attack-result table.
- Transcript viewer.
- Hardening diff viewer.
- Before/after metrics.
- Export button.

### API

FastAPI control plane endpoints:

- `POST /api/scans` (create and queue scan)
- `GET /api/scans` (list scans)
- `GET /api/scans/{scan_id}` (get scan metadata and progress)
- `POST /api/scans/{scan_id}/cancel` (cooperative cancellation aborting active evaluations)
- `GET /api/scans/{scan_id}/events` & `/events/stream` (SSE real-time stream with keepalive)
- `GET /api/scans/{scan_id}/bundle` (complete signed audit bundle ZIP export)
- `GET /api/scans/{scan_id}/findings` (list findings with evidence refs)
- `GET /api/scans/{scan_id}/findings/{finding_id}` (single finding detail)
- `POST /api/scans/{scan_id}/findings/{finding_id}/promote-regression` (promote finding to regression suite)
- `GET /api/scans/{scan_id}/proposal` (view latest prompt diff & policy candidate)
- `GET /api/scans/{scan_id}/policies` (list policy candidates)
- `POST /api/scans/{scan_id}/approve-hardening` (human approval gate)
- `POST /api/scans/{scan_id}/reject-hardening` (human rejection gate)
- `GET /api/scans/{scan_id}/report` (canonical JSON, Markdown, and SARIF 2.1.0 projections)
- `GET /api/regressions` (list persistent regression suite)
- `POST /api/regressions/{regression_id}/toggle` (toggle regression case active/inactive)
- `POST /api/regressions/run` (execute regression-only scan)
- `GET /health` & `GET /ready` (health and readiness probes)

### Orchestrator

Implemented as a strongly-typed **LangGraph `StateGraph`** (`langgraph>=1.2.17`) backed by durable SQLite checkpointing (`SqliteCheckpointSaver`):

```text
initialize_scan
  → recon
  → plan_attacks
  → execute_security_tests
  → judge_results
  → resolve_verdicts
  → generate_hardening_proposal
  → human_approval_interrupt ◄── (LangGraph interrupt gate; awaits human review)
  → retest_security
  → retest_benign_utility
  → calculate_metrics
  → promote_regressions
  → generate_reports
```

See [LANGGRAPH_ORCHESTRATION.md](./LANGGRAPH_ORCHESTRATION.md) for complete state machine, interrupt gate, and checkpointing documentation.

Failure and terminal states: `completed`, `completed_without_retest`, `failed_partial`, `failed_fatal`, `inconclusive`.

### Target adapter

Implemented target adapters:

- `ShopHelperLocalAdapter`: In-memory vulnerable customer support bot with fake customers and simulated `issue_refund` tool.
- `HttpTargetAdapter`: External HTTP targets guarded by strict SSRF defense (blocking private, loopback, link-local, and cloud metadata IPs) and requiring `X-Raven-Scan-Consent: true`.
- `McpTargetAdapter`: Evaluates **Model Context Protocol (MCP)** tool servers across stdio subprocess, in-process, and SSE network transports using JSON-RPC 2.0 handshake, schema inspection, and canary token extraction.
- `PolicyGateway`: Fail-closed runtime wrapper enforcing compiled tool guardrails on simulated tools.

Future adapters:

- Hosted model target directly via API provider.
- RAG document and vector search targets.

### Judge

1. Rule engine checks exact evidence.
2. LLM judge handles semantic cases.
3. Resolver combines results conservatively.

Priority rule:

```text
deterministic confirmed failure > model blocked result
rule/model disagreement → needs_review
no evidence → not_evaluated, not passed
```

### Hardener

Input:

- Confirmed or likely findings
- Target policy
- Existing system prompt
- Tool policy

Output:

- Proposed prompt diff
- Proposed guardrails
- Rationale
- Expected affected cases
- Risk/trade-off notes

### Evidence store

For the MVP, SQLite is sufficient. Store:

- Scans
- Attack cases
- Runs
- Transcripts
- Verdicts
- Hardening proposals
- Retest results
- Events

## 3. Agent responsibilities

### Recon agent

Produces a target profile. It must not attempt aggressive attacks.

### Planner agent

Selects from the approved attack library. It cannot invent arbitrary external actions.

### Attacker agent

Creates a bounded variant of a seed prompt. It cannot access the filesystem, network, or tools beyond the target adapter.

### Judge agent

Returns schema-valid labels and reasons. It cannot mutate target state.

### Hardener agent

Produces a proposal only. It cannot deploy or modify production state.

### Regression runner

Executes fixed attack and benign suites and computes metrics.

## 4. Agent state schema

```json
{
  "goal": "Evaluate ShopHelper for prompt injection and unsafe refund actions",
  "phase": "judging",
  "plan": [
    {"id":"A-01","status":"completed"},
    {"id":"A-02","status":"running"},
    {"id":"A-03","status":"pending"}
  ],
  "confirmed_findings": [],
  "hypotheses": [],
  "missing_evidence": [],
  "approval_requests": [],
  "budget_used": {"model_calls": 12,"tokens": 0},
  "errors": []
}
```

## 5. Implementation status
All core milestones and v1.0 enterprise enhancements have been fully implemented and verified via comprehensive automated test suites (293+ passing tests across the repository):

1. ✅ Built ShopHelper target with simulated tools and synthetic canary injection.
2. ✅ Created versioned attack cases (A-01 to A-18: Catalog v1 and v2) and benign utility cases (B-01 to B-08).
3. ✅ Built target executor and HttpTargetAdapter with SSRF defense.
4. ✅ Built Model Context Protocol (`McpTargetAdapter`) for stdio, in-process, and SSE transports with canary extraction and schema smuggling audits.
5. ✅ Built deterministic judge with exact token, PII, and tool-policy matching.
6. ✅ Built LangGraph StateGraph scan orchestrator with SQLite checkpointer.
7. ✅ Integrated structured LLM judge with schema validation and fallback.
8. ✅ Implemented dual-layer VerdictResolver (with `needs_review` audit queue).
9. ✅ Built PromptHardener (diffs) and PolicyCompiler (runtime tool guardrails).
10. ✅ Implemented Human Approval Interrupt Gate (`POST /approve-hardening`, `POST /reject-hardening`) with atomic concurrency guards (`HTTP 409 Conflict`).
11. ✅ Built security and benign utility regression runners and frontier delta calculations.
12. ✅ Built immutable report generator exporting canonical JSON, Markdown, and SARIF 2.1.0.
13. ✅ Built Next.js web application with live SSE stream, Radar HUD, Constellation view, Evidence drawer, Policy Inspector, and Audit Bundle (.zip) export.
14. ✅ Built standalone CLI runner `raven-test` with `--config`, `--fail-on`, `--output sarif`, `--dry-run`, and Unicode Frontier Scorecard.
15. ✅ Built reusable GitHub Action (`.github/actions/raven-security-scan/`) for automated PR comments, inline code scanning annotations, and SARIF uploads.
16. ✅ Built runtime defense SDK `packages/raven-guard` with fail-closed `PolicyGateway`, `@gateway.protect`, LangGraph/LangChain interceptors, FastAPI middleware, and OpenTelemetry security tracing.
17. ✅ Built end-to-end automated verification and live showcase demonstration script (`scripts/demo_v1.py`).

## 6. Architecture Planes

The v1.0 architecture is organized into clean decoupled planes:

- **Control Plane (`apps/api`):** FastAPI application managing workspaces, scan configurations, findings ledger, policy candidate reviews, report generation, and signed audit bundle exports.
- **Execution Plane (`workers/evaluator`):** Isolated evaluation workers executing LangGraph state machines, target adapters (ShopHelper, HTTP, MCP), deterministic rule engines, and LLM judges.
- **Evidence Plane:** Immutable run artifacts, cryptographic SHA-256 digests, raw transcripts, and tamper-evident audit packages (`GET /api/scans/{id}/bundle`).
- **Runtime Defense Plane (`packages/raven-guard`):** Ultra-lightweight, zero-external-dependency Python SDK deployed in production agents to intercept and enforce compiled policies in real time.
- **Integration Plane:** CLI (`raven-test`), reusable GitHub Action (`raven-security-scan`), and SARIF 2.1.0 feeds for GitHub Code Scanning.

## 7. RAVEN Assurance Layer & Runtime Guard (`raven-guard`)

The core architectural breakthrough of RAVEN is the closed-loop assurance pipeline:

```text
Attack / Evaluation Engine
        ↓
Cryptographic Evidence Ledger
        ↓
Hardening Proposal Generator
        ↓
Runtime Policy Compiler (raven-policy.yaml)
        ↓
Human-in-the-Loop Approval Gate (Atomic HTTP 409)
        ↓
Security + Benign Utility Retest Runner
        ↓
Runtime Enforcement Gateway (raven-guard SDK)
        ↓
Persistent Regression Corpus & CI Gate
```

The runtime policy compiler converts confirmed findings into machine-readable policy candidates (`raven-policy.yaml`). At production runtime, the `raven-guard` package intercepts tool invocations before execution:

```yaml
version: "1.0"
policies:
  - tool: issue_refund
    rules:
      - condition: verified_order_id_present
        action: allow
      - condition: order_missing
        action: deny
        reason: "Refusing refund without verified order ID."
    rate_limits:
      max_calls_per_session: 1
    fail_closed: true
```

When wrapped with `@gateway.protect` or the LangGraph `RavenToolNodeInterceptor`, the policy gateway evaluates incoming arguments against compiled rules. If any violation or prompt injection pattern is detected, execution fails closed instantly, emitting an OpenTelemetry security audit event without calling the downstream tool.

## 8. Persistent Regression Model

A confirmed finding is converted into a versioned test case containing the original target version, attack prompt, expected safe behavior, deterministic success rule, severity, and references. Future scans compare current target responses against the baseline and fail the CI build if the vulnerability reopens.
