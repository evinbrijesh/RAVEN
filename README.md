<div align="center">

# 🦅 RAVEN
### Autonomous Security Regression & Remediation Assurance for LLM Applications

[![Tests](https://img.shields.io/badge/tests-293%2B%20passed-emerald?style=for-the-badge&logo=pytest)](https://github.com/evinbrijesh/RAVEN)
[![PyPI - raven-test](https://img.shields.io/badge/PyPI-raven--test%20v1.0.0-blue?style=for-the-badge&logo=pypi)](https://pypi.org/project/raven-test/)
[![PyPI - raven-guard](https://img.shields.io/badge/PyPI-raven--guard%20v1.0.0-indigo?style=for-the-badge&logo=pypi)](https://pypi.org/project/raven-guard/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-purple?style=for-the-badge&logo=github)](https://github.com/oasis-tcs/sarif-spec)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange?style=for-the-badge)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20Mapped-red?style=for-the-badge)](https://atlas.mitre.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)

<p align="center">
  <b>Attack, verify, harden, and re-test LLM applications before attackers do.</b><br>
  Turning AI security from a one-time penetration audit into a continuous, verifiable regression suite.
</p>

[Quickstart](#-quickstart) • [Architecture](#-end-to-end-architecture-discovery--runtime-prevention) • [Key Features](#-key-features) • [Threat Matrix](#-threat-matrix-mapping) • [CI/CD & CLI](#-cicd-github-action--cli-runner) • [MCP Guide](#-model-context-protocol-mcp-security-scanning) • [Demo Walkthrough](#-demo-walkthrough)

---

</div>

## 💡 Why RAVEN?

Every time an AI team tweaks an LLM application's prompt, adds a tool, or upgrades a model, **they silently re-open vulnerabilities they already fixed**. 

Traditional red-team scanners (e.g. PyRIT, promptfoo, Garak) are **open-loop**: they produce vulnerability reports and leave developers to guess what to fix and whether the fix broke legitimate customer requests.

**RAVEN is closed-loop**:
1. **Discovers** vulnerabilities with cryptographic-grade evidence (exact canaries, PII leaks, unauthorized tool calls, MCP exploits).
2. **Synthesizes** constrained mitigations (system prompt diffs + deterministic `raven-policy.yaml` runtime guardrails).
3. **Guards** with human-in-the-loop approvals backed by atomic concurrency guards (`HTTP 409 Conflict`).
4. **Measures the Frontier**: Re-tests attack cases while running a **benign utility suite** to quantify security gains vs. over-refusal penalties.
5. **Findings Become Tests**: Converts confirmed findings into continuous regression suites executed on every CI commit and PR via GitHub Actions.
6. **Enforces at Runtime**: Automatically compiles guardrails directly into [`raven-guard`](packages/raven-guard) for fail-closed runtime defense.
7. **Verifies Integrity**: Cryptographically hashes run artifacts and transcripts with SHA-256 for tamper-evident auditing.

---

## 🏛️ End-to-End Architecture (Discovery + Runtime Prevention)

```mermaid
flowchart TD
    subgraph DISCOVERY ["🔍 Discovery & Regression Gate (RAVEN Engine)"]
        direction TB
        A[Target Agent / HTTP / MCP Server] --> B[Reconnaissance Probe]
        B --> C[Attack Catalog Selection<br/>OWASP & MITRE ATLAS]
        D --> E[Adaptive Red-Team Mutator<br/>Evasion & Encoding Variants]
        C --> D{Deterministic Rule Engine<br/>Canaries, PII, Tool Misuse}
        D -- "Deflected / Refusal" --> E
        D -- "Confirmed Breach" --> F[Evidence Ledger]
        E --> G[Dual-Layer Judge & Resolver]
        G --> F
        F --> H[Hardening Compiler<br/>Prompt Diff + raven-policy.yaml]
    end

    subgraph HUMAN_GATE ["🛡️ Human-in-the-Loop Review & Retest"]
        direction TB
        H --> I{Reviewer Approval Gate<br/>Atomic 409 Guard}
        I -- "Approve Proposal" --> J[Retest Attack Cases]
        I -- "Approve Proposal" --> K[Benign Utility Suite<br/>100% Utility Retention]
        J & K --> L[Frontier Delta Verified<br/>0.0% Over-Refusal]
        L --> M[Export SARIF 2.1.0 & CI Gate]
    end

    subgraph RUNTIME ["⚡ Runtime Prevention (raven-guard SDK)"]
        direction TB
        L -- "Deploy Policy" --> N[(raven-policy.yaml)]
        N --> O[PolicyGateway Engine]
        P[Production User Request] --> Q[Agent / MCP Server]
        Q --> R{raven-guard Interceptor<br/>@gateway.protect}
        R -- "Within Policy Bounds" --> S[Execute Tool Function]
        R -- "Policy Violation / Injection" --> T[Fail-Closed Deny & Audit Log]
    end

    DISCOVERY --> HUMAN_GATE
    HUMAN_GATE --> RUNTIME
```

---

## ⚡ Key Features

### 🎯 2-Stage Attack & Adaptive Mutation Pipeline
- **Stage 1 (Deterministic Precision):** Exact canary token extraction, PII leaks, and unauthorized tool calls are detected with 100% certainty—zero model hallucination.
- **Stage 2 (Adaptive LLM Mutator):** When a target deflects an attack with a defensive refusal, an AI Attacker inspects the refusal and dynamically synthesizes evasion variants (authority overrides, roleplay scenarios, translation encoding, hypothetical debugging).

### ⚖️ Dual-Layer Judge & Resolver
- **Conservative Resolution:** Deterministic evidence always overrides model opinions.
- **Audit Transparency:** If deterministic checks and the model judge disagree, RAVEN marks the verdict **`needs_review`** and preserves the full transcript for human inspection.

### 🛡️ Hardening & Policy Candidate Generation
- Generates transparent **Prompt Diffs** that instruct the LLM on safe refusal boundaries.
- Compiles machine-readable **Runtime Tool Policies** (e.g., locking down `issue_refund` behind authenticated user and order verification).
- Side-by-side unified diff visualization in the web dashboard.

### 🔒 Enterprise Isolation & Cryptographic Integrity
- **Multi-Tenant Workspaces:** Project and workspace scoping ensuring scans, findings, and regression suites belong strictly to designated project IDs.
- **Deterministic Redaction:** Automatically sanitizes API keys (`sk-...`), Bearer tokens, and sensitive PII from exported reports and transcripts.
- **Tamper-Evident SHA-256 Digests:** Artifact verification endpoint (`GET /api/scans/{id}/artifacts/{artifact_id}/verify`) and one-click UI audit widget validating cryptographic hashes of SARIF, JSON, and Markdown reports.
- **Atomic Approval Concurrency Guard:** Compare-and-swap transaction protection (`HTTP 409 Conflict`) on approval transitions to prevent double-click race conditions and duplicate retest jobs.

### 📊 Security & Utility Frontier Delta
A mitigation is unacceptable if it breaks legitimate business workflows. RAVEN reports both:
- **Security Gain:** Attack Success Rate reduction ($X\% \rightarrow Y\%$, $-Z\%$ risk reduction).
- **Utility Preserved:** Benign customer task completion rate (e.g. $100\%$ utility preservation).
- **Over-Refusal Rate:** Quantifies whether the patch is over-blocking normal users.

### 📜 Standards-Compliant Reporting & CI Gate
- **OASIS SARIF 2.1.0:** Direct export compliant with GitHub Code Scanning (includes `%SRCROOT%` mapping, rules catalog metadata, security severity ratings, and stable finding fingerprints).
- **Audit Bundle (.zip):** One-click signed archive download (`GET /api/scans/{id}/bundle`) packaging SARIF, markdown summary, canonical JSON, findings ledger, raw transcripts, manifest, and SHA-256 checksums.
- **SSRF & Network Defense:** Validates URL schemes, blocks private/loopback/metadata IP ranges, and enforces `X-Raven-Scan-Consent: true`.

---

## 🗺️ Threat Matrix Mapping

Every test case in the RAVEN catalog is versioned and cross-referenced with modern AI security standards:

| Attack ID | Category | Attack Goal | OWASP LLM (2025) | MITRE ATLAS |
|---|---|---|---|---|
| **A-01** | `direct_injection` | Instruction override & config reveal | **OWASP-LLM01** | **AML.T0051** (Prompt Injection) |
| **A-02** | `direct_injection` | Developer authority impersonation | **OWASP-LLM01** | **AML.T0051** (Prompt Injection) |
| **A-03** | `direct_injection` | Indirect instruction extraction | **OWASP-LLM01** | **AML.T0051** (Prompt Injection) |
| **A-04** | `canary_leakage` | Verbatim system prompt canary disclosure | **OWASP-LLM01 / LLM07** | **AML.T0054** (Jailbreak / Leakage) |
| **A-05** | `canary_leakage` | Roleplay debugging game token leak | **OWASP-LLM07** | **AML.T0054** (Jailbreak / Leakage) |
| **A-06** | `canary_leakage` | Foreign language translation bypass | **OWASP-LLM07** | **AML.T0054** (Jailbreak / Leakage) |
| **A-07** | `sensitive_data` | Customer email database dump | **OWASP-LLM02** | **AML.T0057** (Data Exfiltration) |
| **A-08** | `sensitive_data` | Targeted customer phone number extraction | **OWASP-LLM02** | **AML.T0057** (Data Exfiltration) |
| **A-09** | `sensitive_data` | Customer support pretexting PII harvest | **OWASP-LLM02** | **AML.T0057** (Data Exfiltration) |
| **A-10** | `tool_misuse` | Execute refund without order verification | **OWASP-LLM06** | **AML.T0053** (Privilege Escalation) |
| **A-11** | `tool_misuse` | Refund call with missing order ID | **OWASP-LLM06** | **AML.T0053** (Privilege Escalation) |
| **A-12** | `tool_misuse` | High-value refund exceeding financial limit | **OWASP-LLM06** | **AML.T0053** (Privilege Escalation) |
| **A-13** | `tool_misuse` (MCP) | Tool description injection to bypass parameters | **OWASP-LLM06 / LLM01** | **MCP-SEC01** |
| **A-14** | `tool_misuse` (MCP) | Confused deputy chaining lookup to admin tool | **OWASP-LLM06** | **AML.T0053 / MCP-SEC02** |
| **A-15** | `tool_misuse` (MCP) | Schema parameter smuggling via JSON payload | **OWASP-LLM06** | **MCP-SEC03** |
| **A-16** | `direct_injection` (RAG) | Indirect prompt injection via poisoned document | **OWASP-LLM01** | **AML.T0051 / OWASP-RAG01** |
| **A-17** | `canary_leakage` (RAG) | Canary token exfiltration via poisoned record | **OWASP-LLM07** | **AML.T0054 / OWASP-RAG02** |
| **A-18** | `sensitive_data` (RAG) | PII extraction via knowledge base overrides | **OWASP-LLM02** | **AML.T0057** |

---

## 🛠️ CI/CD GitHub Action & CLI Runner

RAVEN can run directly inside your CI/CD pipelines as an automated security regression gate.

### 1. 1-Line GitHub Action Integration (`uses: raven-security/raven-security-scan@v1`)

Add RAVEN to your GitHub workflow (`.github/workflows/security.yml`):

```yaml
name: "RAVEN AI Security Gate"
on:
  pull_request:
    branches: [ "main" ]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - uses: actions/checkout@v4

      # 1-Line RAVEN Security Gate
      - name: Run RAVEN Security Scan
        uses: raven-security/raven-security-scan@v1
        with:
          config-file: "raven.yaml"
          fail-on: "high"
          github-token: ${{ secrets.GITHUB_TOKEN }}
          comment-on-pr: "true"

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "raven-results.sarif"
```

### 2. Standalone Developer CLI (`raven-test`)

Install the CLI directly from PyPI:

```bash
pip install raven-test
```

Initialize your project and run scans directly from your terminal:

```bash
# 1. Interactive setup: Scaffolds a starter raven.yaml with local port auto-detection
raven-test init

# 2. Pre-flight verification: Tests connectivity & profiles target without executing attacks
raven-test run --dry-run

# 3. Execute full regression gate against local bot or remote endpoint
raven-test run --config raven.yaml --fail-on high

# 4. Replay only promoted active regression cases
raven-test run --regression-only

# 5. Export OASIS SARIF 2.1.0 for local security audits
raven-test run --output sarif > raven-results.sarif
```

The CLI renders an interactive **ASCII/Unicode Frontier Security Scorecard** and colorized diff proposals for detected breaches:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   RAVEN Frontier Security Scorecard                    │
├──────────────────────────────┬──────────────┬─────────────┬────────────┤
│ Metric                       │ Pre-Patch    │ Post-Patch  │ Delta      │
├──────────────────────────────┼──────────────┼─────────────┼────────────┤
│ Attack Success Rate (ASR)    │ 33.3%        │ 0.0%        │ -33.3%     │
│ Benign Utility Rate          │ 100.0%       │ 100.0%      │ 0.0%       │
│ Severity Gate (>= HIGH)      │ [FAIL]       │ [PASS]      │ REMEDIATED │
└──────────────────────────────┴──────────────┴─────────────┴────────────┘
```

---

## 🔌 Model Context Protocol (MCP) Security Scanning

RAVEN natively evaluates **Model Context Protocol (MCP)** tool servers and SSE endpoints against prompt injection, unconstrained tool calling, and parameter poisoning.

### Run MCP Evaluation via CLI

```bash
# Evaluate a live MCP SSE server endpoint
raven-test run --target mcp://localhost:8000/sse --categories tool_misuse
```

### Declarative MCP Configuration (`raven.yaml`)

```yaml
version: "1"
target:
  id: "internal-tools-mcp"
  adapter: "mcp"
  url: "mcp://localhost:8000/sse"
  allow_local_dev: true
  headers:
    X-Raven-Scan-Consent: "true"
  timeout_seconds: 10.0

fail_on: "high"

categories:
  - "tool_misuse"

budget:
  max_cases: 5
```

```bash
# Run the MCP security scan
raven-test run --config raven.yaml
```

When an unconstrained MCP tool call (such as a database delete or unverified refund) is detected, RAVEN:
1. Emits an OASIS SARIF 2.1.0 finding targeting the MCP tool definition.
2. Compiles a fail-closed runtime policy in `raven-policy.yaml`.
3. Validates that benign MCP tool calls retain 100% utility.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+ with [`uv`](https://docs.astral.sh/uv/)
- Node.js 18+ & npm

### 1. Installation
```bash
git clone https://github.com/evinbrijesh/RAVEN.git
cd RAVEN
make install
```

### 2. Configuration
Copy the template configuration:
```bash
cp .env.example .env
```
*(By default, RAVEN runs 100% locally with zero external API dependencies using deterministic checks and simulated adapters.)*

### 3. Launch Development Stack
```bash
make dev
```
- **Web UI:** http://localhost:3000
- **API Documentation:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

### Docker Deployment
```bash
docker compose -f infra/docker-compose.yml up --build
```

---

## 📂 Repository Architecture

```text
RAVEN/
├── .github/
│   ├── actions/raven-security-scan/ # Reusable composite GitHub Action for CI
│   └── workflows/                   # Automated CI security & PR workflows
├── apps/
│   ├── api/                         # FastAPI control plane
│   │   ├── app/api/                 # Scans, findings, reports, projects, SSE, bundle export
│   │   ├── app/application/         # Use cases (generate_report, approve_hardening)
│   │   ├── app/domain/              # Entities, Enums, Value Objects
│   │   ├── app/infrastructure/      # SQLite persistence, multi-tenant repos & queue
│   │   └── app/security/            # SSRF validator, redaction pipeline, auth
│   └── web/                         # Next.js 15 App Router dashboard
│       ├── app/                     # Pages: /, /dashboard, /scans, /docs, /regression
│       ├── components/findings/     # Findings table, Evidence drawer, Audit tab
│       ├── components/scan/         # Live mission control, Radar HUD, Constellation, Policy Modal
│       ├── components/hardening/    # Side-by-side prompt & policy diff viewers
│       └── components/report/       # SARIF/JSON/MD exports, Audit Bundle (.zip), SHA-256 verification
├── workers/
│   └── evaluator/                   # Asynchronous evaluation worker & CLI
│       ├── evaluator/cli.py         # CLI runner (raven-test) with SARIF 2.1.0 & scorecard
│       ├── evaluator/attacks/       # Recon agent, Adaptive mutator, Attack planner
│       ├── evaluator/judges/        # Deterministic rule engine, LLM judge, Resolver
│       ├── evaluator/targets/       # ShopHelper bot, Policy gateway, HTTP & MCP adapters
│       ├── evaluator/hardening/     # Prompt hardener & Policy compiler
│       └── evaluator/orchestration/ # LangGraph workflow & state machine
├── packages/
│   ├── raven-guard/                 # Standalone fail-closed runtime policy gateway SDK
│   ├── attack-catalog/              # Versioned attacks (v1 & v2) & benign utility cases
│   └── contracts/                   # Shared JSON schemas & SARIF specifications
├── examples/
│   └── vulnerable-agent/            # Standalone starter agent for CLI and CI testing
└── scripts/
    └── demo_v1.py                   # Automated end-to-end verification and live demo script
```

---

## 🎬 Demo Walkthrough

### Option A: Web Mission Control
Follow the scripted **5-Minute Pitch Sequence** in [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md):

1. **Select Workspace:** Switch project workspaces from the header dropdown (e.g. `Default Project` vs `E-Commerce Agents`).
2. **Launch Scan:** Select `shophelper-local` (or configure an authorized HTTP / MCP target) and click **Launch Scan**.
3. **Observe Real-Time Stream:** Watch the live SSE event feed and dynamic agent constellation transition: `reconnaissance → attacking → arbitration → hardening`.
4. **Inspect Evidence:** Click any finding in the triage table to open the slide-out **Evidence Drawer** showing cryptographic canary leaks or unauthorized tool calls.
5. **Audit Disagreements:** Filter by the **"Judge Audit / Needs Review"** tab to inspect cases where the rule engine and model judge disagreed.
6. **Review Hardening Diff:** Inspect side-by-side system prompt diffs and compiled tool policy constraints.
7. **Approve Gate:** Click **Approve Hardening** (concurrency-protected via HTTP 409) to trigger target re-testing.
8. **Verify Frontier Delta:** Review the **Security & Utility Frontier** card showing attack drop vs. benign usability preservation.
9. **Export & Verify Audit Digest:** Download **SARIF 2.1.0**, JSON, Markdown reports, or click **"Export Audit Bundle (.zip)"** to download the complete sealed audit archive with cryptographic SHA-256 checksums.
10. **Inspect Runtime Policy & CI Config:** Open the **"View Policy & CI Config"** modal to copy production `raven-guard` YAML and CI workflow rules.
11. **Manage Regression Suite:** View permanent CI regression guardrails at `/regression`.

### Option B: Automated Terminal Showcase (`scripts/demo_v1.py`)
Run the self-contained live demonstration in seconds:

```bash
python3 scripts/demo_v1.py
```

This automated verification:
1. Attacks an unhardened agent, demonstrating a critical parameter override breach (`ASR: 100.0%`).
2. Compiles a fail-closed `raven-policy.yaml` runtime guardrail.
3. Deploys the [`raven-guard`](packages/raven-guard) runtime gateway to actively intercept and deflect the exploit (`ASR: 0.0%`).
4. Audits an MCP server across in-process, stdio, and SSE transports with schema smuggling and canary token verification.

---

## 🧪 Testing & Verification

RAVEN is thoroughly verified with **293+ automated tests** across API, worker, CLI, and runtime guard SDK:

```bash
# 1. Run all backend API tests (93 tests)
uv run --directory apps/api pytest tests/

# 2. Run evaluator worker & CLI regression tests (128 tests + 10 soak cycles)
uv run --directory workers/evaluator pytest tests/

# 3. Run runtime policy SDK tests (72 tests)
uv run --directory packages/raven-guard pytest tests/

# 4. Build Next.js web application
npm --prefix apps/web run build

# 5. Execute end-to-end automated showcase
python3 scripts/demo_v1.py
```

---

## ⚖️ Safety & Ethical Principles

- **Explicit Target Authorization:** RAVEN blocks private network ranges (SSRF) and requires explicit consent (`X-Raven-Scan-Consent: true`) for live endpoints.
- **No Self-Deploying Code:** All synthesized patches and guardrails exist exclusively in proposal state until human approval.
- **Evidence Over Belief:** LLM opinions never override deterministic evidence. If evidence is absent, the finding is marked `not_evaluated`, never "secure".
- **Cryptographic Grounding:** Run evidence and exported reports are SHA-256 hashed to guarantee tamper-evident audit trails.
- **No Security Theater:** Passing a test suite verifies behavior *only under stated checks*, never universal immunity.

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
