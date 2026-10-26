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
- `GET /api/scans/{scan_id}/events` (SSE real-time stream)
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
- `PolicyGateway`: Fail-closed runtime wrapper enforcing compiled tool guardrails on simulated tools.

Future adapters:

- Hosted model target directly via API provider.
- RAG document and vector search targets.
- Tool-using agent / MCP server targets.

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
All core milestones have been fully implemented and verified via automated test suites (149 passing tests):

1. ✅ Built ShopHelper target with simulated tools and synthetic canary injection.
2. ✅ Created versioned attack cases (A-01 to A-12) and benign utility cases (B-01 to B-08).
3. ✅ Built target executor and HttpTargetAdapter with SSRF defense.
4. ✅ Built deterministic judge with exact token, PII, and tool-policy matching.
5. ✅ Built LangGraph StateGraph scan orchestrator with SQLite checkpointer.
6. ✅ Integrated structured LLM judge with schema validation and fallback.
7. ✅ Implemented dual-layer VerdictResolver (with `needs_review` audit queue).
8. ✅ Built PromptHardener (diffs) and PolicyCompiler (runtime tool guardrails).
9. ✅ Implemented Human Approval Interrupt Gate (`POST /approve-hardening`, `POST /reject-hardening`).
10. ✅ Built security and benign utility regression runners and frontier delta calculations.
11. ✅ Built immutable report generator exporting canonical JSON, Markdown, and SARIF 2.1.0.
12. ✅ Built Next.js web application with live SSE stream, evidence drawer, and diff viewer.

## 6. Production evolution

After the hackathon, separate the system into:

- Control plane: users, policies, scans, reports.
- Execution plane: isolated workers and target adapters.
- Evidence plane: immutable run artifacts and audit events.
- Model plane: attacker, judge, hardener, and classifier providers.
- Integration plane: CI, GitHub, SARIF, HTTP, RAG, and agent frameworks.

## 7. RAVEN assurance layer

The core architectural addition over a conventional red-team scanner is an assurance layer:

```text
Attack/evaluation engine
        ↓
Evidence ledger
        ↓
Hardening proposal generator
        ↓
Runtime policy compiler
        ↓
Temporary policy gateway
        ↓
Security + utility regression runner
        ↓
Persistent regression corpus
```

The runtime policy compiler converts a confirmed finding into a machine-readable policy candidate. For the MVP, this is a local policy gateway around the simulated `issue_refund` tool. The policy gateway must fail closed and must not perform real external actions.

Example policy candidate:

```json
{
  "tool": "issue_refund",
  "conditions": [
    "verified_order_id_present",
    "verified_user_present",
    "amount_below_threshold"
  ],
  "high_value_action": "human_approval_required",
  "on_violation": "deny_and_log"
}
```

A policy candidate is not considered effective until the original attack is blocked and the benign utility suite passes under the stated evaluation budget.

## 8. Persistent regression model

A confirmed finding is converted into a versioned test case containing the original target version, attack prompt, expected safe behavior, deterministic success rule, severity, and references. Future scans compare the current result with the saved baseline and reopen the finding if the unsafe behavior returns.
