# 🦅 RAVEN: Self-Hosted & Cloud Business Strategy and Product Roadmap

## Executive Recommendation

RAVEN adopts a **self-hosted-first, open-core model**:

* **Community / Self-Hosted Edition is Free:** Complete, unhampered local security engine for developers and security engineers.
* **Managed Cloud Edition is Paid:** Charges for convenience, hosted workers, scheduled scans, team collaboration, retention, and enterprise governance.
* **Identical Core Contracts:** The exact same scan schemas, policy models, regression definitions, and evidence ledgers operate identically across both editions.
* **Privacy by Design:** Security-sensitive organizations keep target traffic, customer data, and raw transcripts strictly inside their own private infrastructure.

We do **not** monetize by taking away or crippling the basic security engine from self-hosted users. Paid value is generated from:

```text
Managed operation
+ Team collaboration & shared workspaces
+ Hosted background workers
+ Automated scan scheduling
+ CI/CD & framework integrations
+ Governance & audit retention
+ Priority enterprise support
+ Private & air-gapped deployment options
```

---

## 1. Product Positioning

> **RAVEN is a continuous security assurance platform for tool-using AI agents. Teams can run it privately in their own infrastructure or use the managed cloud to continuously test, enforce, and monitor AI security regressions.**

The platform presents two complementary experiences:

* **RAVEN Self-Hosted:** You operate the control plane, workers, database, and evidence ledger locally or on private VPCs.
* **RAVEN Cloud:** We operate the control plane, background workers, storage, automated upgrades, and team collaboration layer.

Both share the identical closed-loop guarantee:
```text
Attack ──► Evidence ──► Remediation ──► Approval ──► Retest ──► Continuous Regression
```

---

## 2. Target Customer Segments & Buyers

| Customer Segment | Why They Adopt RAVEN | Preferred Edition |
|---|---|---|
| **AI Startups & Scaleups** | Need to ship tool-using agents fast without hiring dedicated AI red-teamers. Want CI gates to prevent PR disasters. | **Team Cloud** (convenience, zero infra management) |
| **Enterprise AI Platform Teams** | Building internal copilots, RAG agents, and tool backends with sensitive customer/financial data. | **Business / Private Cloud** or **Self-Managed** |
| **Security Consultancies & Red Teams** | Deliver repeatable, standardized client AI security assessments with cryptographic SARIF/PDF evidence. | **Self-Hosted** (client data isolation) |
| **DevSecOps & Platform Engineers** | Enforce automated PR pass/fail checks, SARIF reporting, and vulnerability non-regression in GitHub/GitLab. | **Self-Hosted CLI** $\rightarrow$ **Team Cloud** |
| **AI Agent Framework Vendors** | Integrate runtime tool safety via the `PolicyGateway` SDK to prevent tool hijacking in customer environments. | **`raven-guard` SDK** (Open Core) |

---

## 3. Product Editions & Feature Matrix

```text
   COMMUNITY / FREE            TEAM CLOUD (PAID)           ENTERPRISE (CONTRACT)
 ┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
 │ • Full Security Engine│    │ • Everything in Free │    │ • Dedicated Tenant   │
 │ • raven-test CLI     │    │ • Hosted Workers     │    │ • Private Workers    │
 │ • Local Dashboard    │    │ • Scheduled Scans    │    │ • SSO / SAML / SCIM  │
 │ • PolicyGateway Core │    │ • Team Workspaces    │    │ • Custom Policies    │
 │ • SARIF / JSON Export│    │ • Evidence Retention │    │ • Kubernetes / Helm  │
 │ • GitHub Action (Core│    │ • PR Comments & Bot  │    │ • Custom SLA         │
 └──────────────────────┘    └──────────────────────┘    └──────────────────────┘
```

### Community / Self-Hosted Edition — Free Forever
* **Purpose:** High developer adoption, local testing, research community trust, and organic viral growth.
* **Includes:**
  * Complete local CLI (`raven-test`).
  * Local Next.js mission-control dashboard.
  * Deterministic rule engine + optional user-provided model keys.
  * Full versioned attack & benign catalogs.
  * Local human approval gate and side-by-side prompt diffs.
  * Standalone local `PolicyGateway`.
  * JSON, Markdown, and OASIS SARIF 2.1.0 exports.
  * SQLite local mode + Docker Compose setup.
  * Standard GitHub Action for CI execution.
* *Rule:* Never cripple the local scanner into a marketing demo. Self-hosted users pay in operational effort.

### Team Cloud Edition — Paid SaaS
* **Purpose:** Fast-moving teams that want collaboration without hosting infrastructure.
* **Includes:**
  * Fully managed control plane, PostgreSQL database, and object storage.
  * Hosted background evaluation workers with auto-scaling.
  * Scheduled recurring scans (nightly / weekly regression monitoring).
  * Multi-user workspaces with RBAC (Admin, Developer, Auditor).
  * 90-day centralized evidence and transcript retention.
  * Hosted report history and regression deltas across commits.
  * Target health monitoring, scan cost telemetry, and token usage metrics.
  * Slack, Discord, and Email alerts on security regressions.

### Business / Private Cloud Edition — Paid Enterprise Tier
* **Purpose:** Mid-market organizations with sensitive data, compliance requirements, or internal AI agents.
* **Includes:**
  * Dedicated single-tenant control plane or hybrid customer-hosted workers.
  * SSO / SAML 2.0 / OIDC authentication & SCIM user provisioning.
  * 1-year to unlimited evidence retention with cryptographic hashing.
  * Audit-log streaming to Datadog, Splunk, or AWS S3.
  * Custom target adapters and private corporate model endpoints.
  * Organization-wide regression corpus shared across all engineering teams.
  * Data residency controls (US, EU, APAC regions).

### Enterprise / Self-Managed Edition — Annual Contract
* **Purpose:** Large regulated enterprises (banks, healthcare, defense) requiring full infrastructure air-gapping.
* **Includes:**
  * Production Kubernetes Helm charts and operator.
  * Fully air-gapped / private network execution (zero outbound calls).
  * Customer-Managed Encryption Keys (CMEK).
  * Dedicated enterprise support SLAs and solution architecture assistance.

---

## 4. Monetization & Pricing Model

We avoid volatile, unpredictable per-token pricing that discourages security testing. Instead, we use a **predictable hybrid metric**:

$$\text{Subscription} = \text{Protected AI Applications} + \text{Monthly Scan Runs} + \text{Evidence Retention}$$

* **Developer:** Free forever, 1 local project, community support.
* **Team:** \$499 / month — up to 5 protected AI applications, 150 automated scans/mo, 90-day retention, 5 team seats.
* **Business:** \$1,999 / month — up to 20 applications, 1,000 scans/mo, private workers, SSO, 1-year retention.
* **Enterprise:** Custom contract (\$35,000–\$80,000+ ARR) — unlimited self-managed clusters, custom adapters, SLA.

### Unit Economics
* **Cost per Scan:** $\sim \$0.08$ to $\$0.22$ (capped model calls via Dynamic Evasion Budgeting; $0.00 for deterministic checks).
* **Software Gross Margin:** $> 82\%$.

---

## 5. Deployment Architectures

RAVEN supports three flexible privacy postures:

```text
MODE A: Fully Local (Zero Data Egress)
Browser ──► Local FastAPI ──► Local Worker ──► SQLite Ledger ──► Local Target

MODE B: Hybrid Private (Recommended for Enterprises)
[Customer Private VPC]                            [RAVEN Cloud]
Target App ◄── Private Worker / Connector ──────► Control Plane Dashboard
                      │                                (Metadata & Redacted
                      ▼                                 Scores Only)
         Local Private Evidence Storage

MODE C: Fully Managed Cloud
Target Endpoint (Public/Auth) ◄── RAVEN Hosted Workers ◄── RAVEN Cloud Control Plane
```

---

## 6. The 60-Day Execution Roadmap

---

### 🟢 Days 1–10: Product Foundation & Reliability
* [ ] **Clean Baseline:** Run all API, worker, and frontend tests from a clean checkout; audit database auto-migrations.
* [ ] **Durable State Machine:** Implement SQLite-backed state checkpointing in `workers/evaluator` so scans survive unexpected restarts.
* [ ] **Strict Idempotency:** Ensure approval, retest, and regression promotion cannot execute twice or duplicate database rows.
* [ ] **Explicit Failure Taxonomy:** Surface `completed`, `completed_with_limitations`, `failed_partial`, `failed_fatal`, and `inconclusive`.
* [ ] **Sensitive Redaction:** Mask authorization tokens, PII, and API keys before logging transcripts.
* [ ] **Exit Gate:** 10 consecutive full scans execute without manual database cleanup; mid-scan kill recovers gracefully.

---

### 🟡 Days 11–22: Developer Distribution Wedge
* [ ] **`raven-test` CLI:** Package an installable Python CLI with rich terminal diff viewer.
* [ ] **Declarative `raven.yaml`:** Standardize configuration for targets, budgets, and severity thresholds.
* [ ] **Regression-Only Mode:** Fast sub-second CI execution running only promoted regression cases.
* [ ] **GitHub Action:** Build `actions/raven-security-scan` with PR comments, checks annotations, and SARIF upload.
* [ ] **Starter Repo:** Publish `raven-starter-demo` for immediate 1-click evaluation.
* [ ] **Exit Gate:** A developer can clone the starter repo, trigger a PR regression, and inspect a SARIF failure in $< 5$ minutes.

---

### 🟠 Days 23–36: Standalone `raven-guard` Runtime SDK
* [ ] **Package Extraction:** Extract the PolicyGateway into a standalone package (`packages/raven-guard`).
* [ ] **Fail-Closed Engine:** Enforce strict tool parameter validation, rate thresholds, and authorization claims.
* [ ] **Framework Decorators:** Implement `@gateway.protect(tool="...")` and LangChain/LangGraph middlewares.
* [ ] **Dry-Run Mode:** Enable zero-risk production telemetry logging without dropping user calls.
* [ ] **Audit Streaming:** Stream policy violation events to OpenTelemetry and SIEM loggers.
* [ ] **Exit Gate:** A jailbroken agent is strictly blocked from executing unauthorized tool actions at runtime.

---

### 🔵 Days 37–48: Cloud Multi-Tenant Foundation
* [ ] **Multi-Tenancy Models:** Implement Users, Workspaces, Projects, and Target Registrations.
* [ ] **PostgreSQL & S3 Repositories:** Add enterprise database and S3-compatible evidence storage adapters.
* [ ] **Hosted Queue & Workers:** Enable remote worker job dispatching with heartbeat monitoring.
* [ ] **Cross-Project Dashboard:** Centralize security health, regression counts, and token budget analytics.
* [ ] **Exit Gate:** Two separate workspaces run scans concurrently with zero data leakage across tenants.

---

### 🟣 Days 49–60: Integrations & Private Beta Launch
* [ ] **MCP Target Adapter:** Implement Model Context Protocol adapter to audit agent tool discovery and schemas.
* [ ] **Indirect Prompt Injection:** Add 6 test cases covering knowledge base and RAG document poisoning.
* [ ] **Design Partner Onboarding:** Deploy private beta with 3–5 early-stage AI startups and consultancies.
* [ ] **Telemetry & Feedback Loop:** Measure time-to-first-scan, conversion from self-hosted CLI to cloud, and bug reports.
* [ ] **Exit Gate:** External beta users connect a custom agent and catch a regression without developer assistance.

---

## 7. Key Business & Velocity Metrics

1. **Time to First Value:** $< 5$ minutes from `uv pip install raven-test` to first SARIF report.
2. **Weekly Active Scans:** Number of automated scans run via CI/CD.
3. **Regression Prevention Count:** Number of broken Git commits blocked by RAVEN before production.
4. **Self-Hosted to Cloud Conversion Rate:** Target $8–12\%$ of active open-source teams upgrading to Team Cloud for hosted features.
5. **Gross Margin per Scan:** Maintained $> 80\%$ via deterministic pre-filtering and early-stopping mutators.
