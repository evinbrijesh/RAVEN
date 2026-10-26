# 🦅 RAVEN Accelerated 28-Day Production Execution Plan
### Fast-Track Roadmap: From Hackathon Prototype to Production-Ready AI Security Platform

---

## 🎯 Executive Summary & Strategic Shift

The original roadmap outlined a standard 90-day enterprise timeline. With **dedicated daily hands-on engineering**, this timeline is compressed from **90 days down to an aggressive, realistic 28-day (4-Week) sprint**.

We are **not** trying to build a generic AI scanner for every possible model and framework. Instead, we are executing on RAVEN’s high-conviction wedge:

> **RAVEN is the continuous security regression engine and runtime policy enforcement layer for tool-using AI agents.**

```text
               THE 28-DAY ACCELERATED PIPELINE

   WEEK 1                  WEEK 2                  WEEK 3                  WEEK 4
[Days 1–7]              [Days 8–14]             [Days 15–21]            [Days 22–28]
Reliability &           Developer CI/CD         Runtime Policy          MCP & Advanced
Restart-Safety          & GitHub Action         Gateway SDK             Threat Coverage
      │                       │                       │                       │
      ▼                       ▼                       ▼                       ▼
• Zero-debt baseline    • raven-test CLI        • raven-guard PyPI      • MCP tool audits
• Durable checkpoints   • raven.yaml config     • Tool schema validator • Indirect injection
• Idempotent nodes      • GitHub Action         • Fail-closed gateway   • RAG poisoning
• Strict redaction      • PR comments + SARIF   • LangGraph decorators  • v1.0 Launch
```

---

## 📅 The 28-Day Daily Sprint Breakdown

---

### 🟢 WEEK 1 (Days 1–7): Zero-Debt Baseline & Bulletproof Reliability
**Primary Objective:** Make the current workflow 100% dependable, restart-safe, and free of manual database resets.

#### Day 1: Truth Audit & Clean Baseline
* [ ] Run backend tests (`pytest`) and frontend production build (`next build`) from a fresh checkout.
* [ ] Execute a full scan on a blank SQLite database; audit that all database migrations run automatically.
* [ ] Remove or cleanly label any hardcoded demo mocks in the worker pipeline so production paths strictly use real graph transitions.
* [ ] Verify the deterministic engine runs with zero external API dependencies when offline.

#### Day 2–3: Durable State Machine & Worker Checkpointing
* [ ] Implement SQLite-backed state checkpointing in `workers/evaluator/evaluator/orchestration/checkpoint.py`.
* [ ] Ensure worker crashes or restarts mid-scan resume safely from the exact interrupted node (`recon` $\rightarrow$ `attack` $\rightarrow$ `judge` $\rightarrow$ `harden`).
* [ ] Enforce idempotency: re-running a completed node or retrying a failed attempt must never duplicate findings, database rows, or event logs.
* [ ] Implement an explicit timeout and cleanup handler for orphaned background jobs.

#### Day 4: Strict Failure Taxonomy & Error Boundaries
* [ ] Replace generic exceptions with typed errors: `TargetUnreachableError`, `BudgetExceededError`, `ModelTimeoutError`, `InvalidEvidenceError`.
* [ ] Enforce the 5 explicit terminal statuses in the database: `completed`, `completed_with_limitations`, `failed_partial`, `failed_fatal`, `inconclusive`.
* [ ] Guarantee: An interrupted run or model failure **never** silently turns into a clean "pass".

#### Day 5: Sensitive Data Redaction & Evidence Hashing
* [ ] Build a deterministic redaction pipeline for all logged transcripts: mask API keys, auth headers, email addresses, and phone numbers before writing to SQLite.
* [ ] Implement cryptographic run hashes (SHA-256 over prompt + tool calls + target version + response) ensuring every verdict is auditable and tamper-proof.
* [ ] Write automated tests asserting that secrets in system prompts never leak into exported reports.

#### Day 6–7: End-to-End Contract & Regression Verification
* [ ] Write automated end-to-end integration tests that spin up API + Worker + ShopHelper target, execute a 12-case scan, approve hardening, and verify that the retest delta succeeds.
* [ ] Verify duplicate approvals on `/api/scans/{id}/approve-hardening` return HTTP 409 Conflict without spawning duplicate retests.
* [ ] **Week 1 Gate:** The entire scan, approval, and report lifecycle runs reliably 10 consecutive times without errors or manual intervention.

---

### 🟡 WEEK 2 (Days 8–14): Developer CI/CD Wedge & GitHub Action
**Primary Objective:** Enable developers to run RAVEN as a automated pull-request gate in under 5 minutes.

#### Day 8–9: Standalone `raven-test` CLI
* [ ] Package `raven-test` as an installable Python CLI tool (`uv pip install raven-test`).
* [ ] Implement simple, human-friendly subcommands:
  * `raven-test run --config raven.yaml`
  * `raven-test regression --fail-on high`
  * `raven-test report --format sarif --out results.sarif`
* [ ] Add rich terminal output (colorized diff viewer, progress spinners, clear before/after table).

#### Day 10: Declarative `raven.yaml` Configuration
* [ ] Define the official project configuration schema:
  ```yaml
  version: "1"
  target:
    type: "http"
    endpoint: "http://localhost:8000/v1/chat"
    headers:
      X-Raven-Scan-Consent: "true"
  suite:
    categories: ["direct_injection", "canary_leakage", "tool_misuse", "sensitive_data"]
    budget:
      max_attacks: 12
      max_model_calls: 36
  gate:
    fail_on_severity: "high"
    max_benign_utility_drop: 0.0
  ```
* [ ] Add schema validation (`pydantic`) with helpful diagnostic error messages on invalid fields.

#### Day 11–12: Official GitHub Action (`actions/raven-security-scan`)
* [ ] Create GitHub Action repository structure (`action.yml` + runner script).
* [ ] Implement PR comment generation:
  * Attack Success Rate (ASR) before vs. after.
  * Legitimate customer utility pass rate.
  * Direct diff preview of the proposed prompt hardening.
* [ ] Add GitHub Check Annotations pointing directly to the line of code or tool definition that caused the failure.

#### Day 13: SARIF 2.1.0 & GitHub Code Scanning Integration
* [ ] Validate exported SARIF 2.1.0 output against the OASIS standard validator.
* [ ] Ensure SARIF files upload cleanly to GitHub Security Tab (`github/codeql-action/upload-sarif`).
* [ ] Verify vulnerability severity mapping (`critical` $\rightarrow$ `error`, `high` $\rightarrow$ `error`, `medium` $\rightarrow$ `warning`).

#### Day 14: Sample Repo & One-Click Template
* [ ] Create `raven-starter-demo` repository showing how to guard an AI agent in GitHub Actions.
* [ ] Record a 60-second Loom/GIF demonstration of a PR being blocked due to prompt injection and auto-fixed via RAVEN diff.
* [ ] **Week 2 Gate:** A developer can clone a repo, run `raven-test`, and block a vulnerable Git commit in CI/CD within 5 minutes.

---

### 🟠 WEEK 3 (Days 15–21): Standalone Runtime PolicyGateway SDK
**Primary Objective:** Transition from purely finding vulnerabilities to preventing them at runtime.

```text
   DISCOVERY (RAVEN Engine)           RUNTIME PREVENTION (raven-guard)
  ┌─────────────────────────┐       ┌─────────────────────────────────┐
  │ 1. Attacks Target       │       │ 1. Intercepts LLM tool call     │
  │ 2. Detects Unauthorized │ ────► │ 2. Enforces validated policy    │
  │    Refund               │       │ 3. Fails closed on unauthorized │
  │ 3. Compiles JSON Policy │       │    parameters or missing auth   │
  └─────────────────────────┘       └─────────────────────────────────┘
```

#### Day 15–16: Core SDK Architecture (`raven-guard`)
* [ ] Extract `PolicyGateway` into a standalone, zero-dependency package (`packages/raven-guard`).
* [ ] Implement the core `authorize()` API:
  ```python
  from raven_guard import PolicyGateway, PolicyContext

  gateway = PolicyGateway.from_yaml("raven-policy.yaml")
  decision = await gateway.authorize(
      tool="issue_refund",
      arguments={"order_id": "1001", "amount": 250.00},
      context=PolicyContext(user_verified=True, order_verified=True)
  )
  if not decision.allowed:
      raise PermissionError(decision.reason)
  ```
* [ ] Implement fail-closed architecture: if the policy is missing or arguments don't match, calls are denied and logged.

#### Day 17: Framework Integrations & Decorators
* [ ] Add native Python decorators for rapid developer integration:
  ```python
  @gateway.protect(tool="issue_refund")
  async def issue_refund(order_id: str, amount: float):
      ...
  ```
* [ ] Build middleware for **LangChain** and **LangGraph** tool nodes to intercept and enforce policy boundaries automatically.

#### Day 18: Dynamic Financial & Risk Thresholds
* [ ] Add condition evaluators for:
  * Maximum single transaction amounts (e.g., refunds $> \$100$ require manager approval).
  * Rate-limiting per user/session.
  * Required authorization claims (e.g., `user_id` must match `order.customer_id`).
* [ ] Add structured audit logging (emitting OpenTelemetry-compatible security trace events).

#### Day 19–20: Policy Dry-Run Mode & Compiler Sync
* [ ] Implement `dry_run = True` mode: log policy violations to observability tools without breaking user requests (crucial for safe production rollouts).
* [ ] Ensure the Hardening Agent in RAVEN outputs policies directly compatible with `raven-guard.yaml`.

#### Day 21: Unit Test Suite & Documentation
* [ ] Write 100% test coverage on `raven-guard` condition evaluations and edge cases.
* [ ] Publish comprehensive README with integration guides for FastAPI, LangChain, and LangGraph.
* [ ] **Week 3 Gate:** An application using `raven-guard` blocks unauthorized tool calls even when the LLM is jailbroken into invoking them.

---

### 🔴 WEEK 4 (Days 22–28): MCP Integration & Advanced Threat Suite
**Primary Objective:** Connect to the standard Model Context Protocol (MCP) and expand into modern agent threats.

#### Day 22–23: Model Context Protocol (MCP) Target Adapter
* [ ] Build an MCP Client Adapter in `evaluator/targets/mcp_adapter.py`.
* [ ] Connect RAVEN to any local or remote MCP server via stdio or Server-Sent Events (SSE).
* [ ] Automatically parse MCP tool definitions, descriptions, and input schemas to generate target profiles.

#### Day 24: MCP Tool Security Audit Vectors
* [ ] Implement attack vectors specific to MCP tool calling:
  * **Tool Description Injection:** Attacker prompts trying to redefine tool schemas.
  * **Confused Deputy Attacks:** Tricking an agent into chaining a public tool into an internal administrative tool.
  * **Schema Parameter Smuggling:** Injecting prompt payloads into unstructured string parameters.

#### Day 25–26: Indirect Prompt Injection & RAG Poisoning Tests
* [ ] Add 6 versioned test cases to `packages/attack-catalog/attacks/attacks-v2.json`:
  * Hidden instruction overrides embedded inside retrieved knowledge documents.
  * Fake customer records containing canary tokens and instructions to overwrite bot rules.
* [ ] Validate that the Deterministic Judge identifies indirect leaks without false positives.

#### Day 27: Web Mission Control Polish & v1.0 Packaging
* [ ] Update the Next.js UI to support uploading custom `raven.yaml` files and inspecting `raven-guard` runtime policies.
* [ ] Export complete end-to-end audit bundles (SARIF 2.1.0 + Markdown Executive Summary + Raw Evidence Ledger).
* [ ] Perform a full security scan on RAVEN itself (dependency audits, Dockerfile non-root user verification, input sanitization).

#### Day 28: v1.0 Launch & Public Release
* [ ] Tag `v1.0.0` on GitHub.
* [ ] Publish `raven-test` and `raven-guard` to PyPI.
* [ ] Write the official Launch Announcement / Blog Post highlighting the 28-day journey from hackathon to production.
* [ ] **Final Milestone:** Deliver a live demo of RAVEN protecting an agent in CI/CD and enforcing runtime guardrails via `raven-guard`.

---

## ⚡ Daily Operating Rhythm for High-Velocity Execution

To maintain momentum over 28 consecutive days, follow this daily 3-step discipline:

| Time of Day | Action | Focus |
|---|---|---|
| **Morning (15 mins)** | **Target Lock** | Review the single bullet point for the day. Define the exact test case that proves it is done. |
| **Core Dev Block** | **Test-Driven Implementation** | Write the test first $\rightarrow$ write the minimal code $\rightarrow$ verify tests pass (`make test`). |
| **Evening (15 mins)** | **Commit & Validate** | Push a clean, green commit with clear commit message (`feat(cli): ...` or `test(worker): ...`). Keep `main` deployable every night. |

---

## 📊 Key Progress Metrics (How to Measure Success)

| Metric | Day 1 Baseline | Day 14 Target | Day 28 Final Target |
|---|---|---|---|
| **CI Integration Time** | Manual script only | $< 5$ minutes | 1-line GitHub Action |
| **Test Suite Coverage** | 91 tests | $> 130$ tests | $> 175$ tests |
| **Scan Reliability** | Local runs only | 100% restart-safe | Production-grade failover |
| **Runtime Enforcement** | Proposed diff only | Dry-run SDK | Live `raven-guard` SDK |
| **Standard Integrations** | Local ShopHelper | HTTP + GitHub Action | HTTP + GitHub + MCP |
| **Supported Threats** | 12 seed attacks | 12 core + regression | 18 attacks (inc. RAG & MCP) |

---

## 🏁 Summary Checklist: Where We Stand

- [x] Hackathon MVP Complete (FastAPI + Worker + Next.js + LangGraph)
- [ ] **Week 1:** Production Reliability & Restart-Safe Checkpointing
- [ ] **Week 2:** Developer CLI (`raven-test`) & GitHub Action CI/CD Gate
- [ ] **Week 3:** Standalone Runtime Policy Gateway SDK (`raven-guard`)
- [ ] **Week 4:** MCP Adapter, RAG Threat Vectors, & v1.0 Release
