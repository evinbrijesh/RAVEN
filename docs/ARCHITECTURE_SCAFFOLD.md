# RAVEN Architecture and Scaffolding Blueprint

**Product:** RAVEN — Red-team Analysis, Verification, Enforcement, and Normal-use Assurance

**Scope:** Production-shaped hackathon MVP with a clear path to deployment

---

## 1. Recommended architecture

Use a modular monolith with isolated workers, not microservices.

```text
┌────────────────────────────────────────────────────────────┐
│                     Next.js Web Application                │
│  Scan setup · Live progress · Findings · Diff · Report     │
└───────────────────────────┬────────────────────────────────┘
                            │ HTTPS + SSE
┌───────────────────────────▼────────────────────────────────┐
│                     FastAPI Control Plane                  │
│ Auth · scan API · policy API · report API · SSE events     │
└───────────────┬───────────────────────┬────────────────────┘
                │                       │
        ┌───────▼────────┐      ┌──────▼─────────┐
        │ PostgreSQL      │      │ Redis           │
        │ scans, findings │      │ job queue/events│
        │ policies, audit │      │                 │
        └─────────────────┘      └──────┬─────────┘
                                        │
                                ┌───────▼────────┐
                                │ RAVEN Worker    │
                                │ state machine   │
                                │ target adapter  │
                                │ judges          │
                                │ hardener        │
                                │ retest runner   │
                                └───────┬─────────┘
                                        │
                     ┌──────────────────▼──────────────────┐
                     │ Isolated evaluation target          │
                     │ ShopHelper + policy gateway         │
                     │ no real external side effects       │
                     └─────────────────────────────────────┘
```

### Why this architecture

A modular monolith is fast to build, easy to deploy, and still gives you clean
production boundaries. The worker is separated from the API so long-running
scans do not block web requests. PostgreSQL provides durable state and Redis
provides queueing and live event delivery. You can run the complete MVP with
Docker Compose and later split the worker or evaluation plane into separate
services without rewriting the domain model.

**Do not** begin with Kubernetes, Kafka, Temporal, a service mesh, or multiple
independent repositories. They add operational risk without improving the
hackathon demo.

---

## 2. Recommended technology stack

| Layer | Recommendation | Reason |
| --- | --- | --- |
| Web | Next.js, TypeScript, Tailwind, shadcn/ui | Fast polished UI and strong form/table support |
| API | Python FastAPI, Pydantic v2 | Good fit for AI orchestration and strict schemas |
| Worker | Python worker using ARQ or RQ | Simple Redis-backed asynchronous jobs |
| Database | PostgreSQL | Durable scans, evidence, policies, audit history |
| Queue/events | Redis | Job queue, progress events, short-lived state |
| AI provider | Provider adapter; LiteLLM optional | Avoid coupling the domain to one model vendor |
| Structured output | Pydantic validation | Reject malformed model responses safely |
| Observability | OpenTelemetry plus structured logs | Trace scan phases and model-call latency |
| Local development | Docker Compose | Reproducible setup for the team and judges |
| Deployment | One web service, one worker, managed Postgres/Redis | Simple production-shaped deployment |
| File storage | Local volume in MVP; S3-compatible storage later | Avoid object-storage complexity initially |

### MVP simplification

For the first working slice, use **SQLite and an in-process worker** if
Redis/PostgreSQL setup threatens the demo. The domain interfaces must still
look like PostgreSQL and a queue are available later. Move to PostgreSQL and
Redis before final deployment if time permits.

---

## 3. Monorepo layout

```text
raven/
├── apps/
│   ├── web/                         # Next.js frontend
│   │   ├── app/
│   │   │   ├── page.tsx             # dashboard
│   │   │   ├── scans/new/page.tsx   # scan setup
│   │   │   ├── scans/[id]/page.tsx  # live scan/report
│   │   │   └── api/                 # frontend-only routes if needed
│   │   ├── components/
│   │   │   ├── scan/
│   │   │   ├── findings/
│   │   │   ├── hardening/
│   │   │   └── report/
│   │   ├── lib/
│   │   │   ├── api-client.ts
│   │   │   └── sse-client.ts
│   │   └── package.json
│   │
│   └── api/                         # FastAPI control plane
│       ├── app/
│       │   ├── main.py
│       │   ├── config.py
│       │   ├── dependencies.py
│       │   ├── api/
│       │   │   ├── scans.py
│       │   │   ├── findings.py
│       │   │   ├── policies.py
│       │   │   ├── reports.py
│       │   │   └── events.py
│       │   ├── domain/
│       │   │   ├── enums.py
│       │   │   ├── entities.py
│       │   │   ├── value_objects.py
│       │   │   └── errors.py
│       │   ├── application/
│       │   │   ├── create_scan.py
│       │   │   ├── get_scan.py
│       │   │   ├── approve_hardening.py
│       │   │   └── generate_report.py
│       │   ├── infrastructure/
│       │   │   ├── db/
│       │   │   ├── queue/
│       │   │   ├── events/
│       │   │   └── storage/
│       │   └── security/
│       │       ├── redaction.py
│       │       ├── authorization.py
│       │       └── limits.py
│       ├── migrations/
│       ├── tests/
│       └── pyproject.toml
│
├── packages/
│   ├── contracts/                   # shared JSON/OpenAPI schemas
│   ├── attack-catalog/              # versioned attack and benign cases
│   │   ├── attacks/
│   │   └── benign/
│   └── ui/                          # optional shared UI primitives
│
├── workers/
│   └── evaluator/
│       ├── worker.py
│       ├── orchestration/
│       │   ├── state_machine.py
│       │   ├── phases.py
│       │   └── budgets.py
│       ├── targets/
│       │   ├── base.py
│       │   ├── shophelper.py
│       │   └── policy_gateway.py
│       ├── attacks/
│       │   ├── planner.py
│       │   ├── executor.py
│       │   └── mutation.py
│       ├── judges/
│       │   ├── deterministic.py
│       │   ├── semantic.py
│       │   └── resolver.py
│       ├── hardening/
│       │   ├── prompt_hardener.py
│       │   ├── policy_compiler.py
│       │   └── proposal_validator.py
│       ├── regression/
│       │   ├── security_runner.py
│       │   ├── utility_runner.py
│       │   └── metrics.py
│       └── tests/
│
├── fixtures/
│   ├── shophelper/
│   │   ├── system-prompt.txt
│   │   ├── fake-customers.json
│   │   ├── tools.json
│   │   └── vulnerable-policy.json
│   └── demo-scan.json
│
├── infra/
│   ├── docker-compose.yml
│   ├── Dockerfile.api
│   ├── Dockerfile.worker
│   ├── Dockerfile.web
│   └── nginx.conf                 # optional production reverse proxy
│
├── docs/
│   ├── PRD.md
│   ├── DATA_FLOW.md
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── API_CONTRACT.md
│   └── ARCHITECTURE_SCAFFOLD.md
│
├── .env.example
├── .gitignore
├── CLAUDE.md
├── LICENSE
├── README.md
├── SECURITY.md
└── Makefile
```

---

## 4. Domain boundaries

### Control plane

The control plane owns users, scan configuration, scan lifecycle, approvals,
policies, reports, and audit events. It must never directly execute target
prompts or model calls in the request thread.

### Evaluation plane

The evaluation worker owns reconnaissance, attack execution, judging,
hardening proposals, and retesting. It receives a scan ID and loads all
configuration from durable storage. It emits progress events and persists
every meaningful state transition.

### Target plane

A target adapter exposes a narrow interface. The target plane owns the
ShopHelper simulation and the temporary policy gateway. It must not expose
arbitrary shell commands, network requests, or real-world side effects.

### Evidence plane

The evidence plane stores transcripts, deterministic signals, judge outputs,
proposal diffs, approval events, retest results, and report artifacts. Every
finding references evidence IDs rather than copying untrusted text into
multiple places.

### Model plane

The model plane exposes attacker, judge, hardener, and classifier roles
through provider-neutral interfaces. Model output is untrusted and must pass
schema and policy validation before entering the domain state.

---

## 5. Core interfaces

### Target adapter

```python
class TargetAdapter(Protocol):
    async def profile(self) -> TargetProfile: ...
    async def invoke(self, request: TargetRequest) -> TargetResponse: ...
    async def reset(self) -> None: ...
    async def apply_temporary_policy(self, policy: PolicyCandidate) -> None: ...
    async def clear_temporary_policy(self) -> None: ...
```

### Judge interface

```python
class Judge(Protocol):
    async def evaluate(
        self,
        attack_case: AttackCase,
        transcript: Transcript,
    ) -> JudgeResult: ...
```

### Policy gateway

```python
class PolicyGateway(Protocol):
    def authorize(
        self,
        tool_name: str,
        arguments: dict,
        context: ToolContext,
    ) -> PolicyDecision: ...
```

### Regression runner

```python
class RegressionRunner(Protocol):
    async def run_security(self, target: TargetAdapter, cases: list[AttackCase]) -> TestRun: ...
    async def run_utility(self, target: TargetAdapter, cases: list[BenignCase]) -> TestRun: ...
```

---

## 6. Scan state machine

```text
CREATED
  ↓
RECONNING
  ↓
ATTACKING
  ↓
JUDGING
  ↓
HARDENING_PROPOSED
  ↓
AWAITING_APPROVAL
  ├── rejected → COMPLETED_WITHOUT_RETEST
  └── approved → RETESTING
                    ↓
              REGRESSION_SAVED
                    ↓
                 REPORTING
                    ↓
                COMPLETED
```

Any phase can transition to `FAILED_PARTIAL` when individual cases time out
or a model provider fails. A scan must never transition to `COMPLETED` with a
blank or missing result set.

---

## 7. Database tables

Minimum durable tables:

- `scans`
- `scan_events`
- `target_profiles`
- `attack_cases`
- `attack_runs`
- `transcripts`
- `verdicts`
- `findings`
- `hardening_proposals`
- `policy_candidates`
- `approvals`
- `regression_cases`
- `test_runs`
- `report_artifacts`

Important indexes:

- `scan_events(scan_id, created_at)`
- `attack_runs(scan_id, attack_case_id)`
- `findings(status, severity)`
- `regression_cases(target_id, attack_case_id, active)`

---

## 8. Runtime security controls

The MVP should enforce these controls in code, not only in documentation:

1. Built-in target allowlist.
2. No arbitrary URL input.
3. No shell or filesystem tools for agents.
4. Fake canary and synthetic customer data only.
5. Maximum 12 attack cases.
6. Maximum 2 attempts per attack.
7. Maximum model-call and token budget.
8. Per-call timeout.
9. Global scan timeout.
10. Concurrency limit.
11. Model-output schema validation.
12. Redaction before persistence and external telemetry.
13. Human approval before applying a policy candidate.
14. Separate security and utility results.
15. Explicit partial and needs-review statuses.

---

## 9. Deployment profiles

### Hackathon profile

```text
Next.js + FastAPI + one worker process + SQLite + optional Redis
```

Run with one command:

```bash
make dev
```

### Small production profile

```text
Next.js service
FastAPI service
One or more evaluator workers
Managed PostgreSQL
Managed Redis
Object storage for evidence artifacts
OpenTelemetry collector
```

Use a reverse proxy or managed ingress for TLS, rate limiting, and
request-size limits.

### Enterprise profile

Add tenant isolation, customer-managed encryption keys, private model
gateways, self-hosted workers, retention policies, SSO/RBAC, audit export,
and network egress controls.

---

## 10. Implementation order for 24 hours

### Developer track

1. Create the monorepo and CI check.
2. Build ShopHelper and the policy gateway.
3. Implement attack-case schemas and deterministic judge.
4. Implement the scan state machine.
5. Add structured model judge.
6. Add hardening proposal and policy compiler.
7. Add security and utility regression runners.
8. Add API endpoints and SSE events.
9. Add persistence if the happy path is stable.
10. Run failure-injection tests and freeze features.

### Design/documentation track

1. Finalize the RAVEN visual identity and information hierarchy.
2. Design scan setup, live progress, findings, proposal, approval, and report states.
3. Author the 8–12 attack cases and 8–10 benign cases.
4. Define expected safe behavior for every case.
5. Prepare synthetic ShopHelper fixtures.
6. Write evidence explanations and OWASP references.
7. Test the UI states with the developer's partial backend.
8. Prepare the demo script, backup recording, README, and pitch.

---

## 11. Definition of done

RAVEN is ready for the hackathon when a clean checkout can start the local
stack, create a scan, show live progress, reproduce at least one deterministic
failure, propose a prompt/policy change, require approval, block the repeated
attack, pass benign tasks, save a regression case, and export a report without
an unhandled error.

The product is **not** ready if the only successful behavior is a static
dashboard or a hardcoded report. The demo must execute a real target
interaction and produce evidence from the current run.
