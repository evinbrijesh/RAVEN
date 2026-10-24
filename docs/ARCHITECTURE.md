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

FastAPI endpoints:

- `POST /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/events`
- `GET /api/scans/{scan_id}/findings`
- `POST /api/scans/{scan_id}/approve-hardening`
- `GET /api/scans/{scan_id}/report`

### Orchestrator

Implement as a typed state machine rather than an unconstrained autonomous loop:

```text
CREATED
  → RECON
  → ATTACKING
  → JUDGING
  → HARDENING_PROPOSED
  → AWAITING_APPROVAL
  → RETESTING
  → REPORTING
  → COMPLETED
```

Failure state: `FAILED_PARTIAL` or `FAILED_FATAL`.

### Target adapter

MVP adapter:

- `ShopHelperLocalAdapter`
- In-memory or local HTTP target
- Simulated `issue_refund` tool
- No real side effects

Future adapters:

- Authorized HTTP endpoint
- Hosted model target
- RAG document target
- Tool-using agent target

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

## 5. Recommended implementation order

1. Build ShopHelper and its deterministic tool policy.
2. Build attack case schema and seed library.
3. Build target executor.
4. Build deterministic judge.
5. Build scan state machine.
6. Add structured LLM judge.
7. Add hardening proposal and approval screen.
8. Add regression runner.
9. Add report and metrics.
10. Add SSE progress and UI polish.

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
