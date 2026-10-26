# RAVEN Documentation Pack

RAVEN is an autonomous security regression and remediation assurance system for LLM applications. It attacks a controlled target, verifies findings using deterministic checks and an AI judge, proposes constrained hardening diffs and runtime tool policies, and retests both security and normal user behavior.

## Documents

- [PRD](./PRD.md) — Product vision, MVP scope, requirements, metrics, backlog, and architecture boundaries.
- [Architecture](./ARCHITECTURE.md) — System components, domain model, agent responsibilities, and remediation loop.
- [LangGraph Orchestration](./LANGGRAPH_ORCHESTRATION.md) — Production LangGraph StateGraph, SQLite checkpointer, interrupt gates, and resume lifecycle.
- [Data Flow](./DATA_FLOW.md) — Trust boundaries, data classification, event streaming, evidence ledger, and failure paths.
- [Threat Model](./THREAT_MODEL.md) — Assets, threats, SSRF defenses, consent verification, and safety controls.
- [API Contract](./API_CONTRACT.md) — REST & SSE endpoints, schemas, regression endpoints, reports, and error models.
- [Coding Instructions (Historical)](./CLAUDE.md) — Initial coding guidelines (see canonical root `CLAUDE.md` for current rules).
- [Architecture Blueprint](./ARCHITECTURE_SCAFFOLD.md) — Modular monolith structure, data models, and component scaffolds.
- [Demo Script](./DEMO_SCRIPT.md) — Scripted 5-minute live pitch sequence and fallback playbook.
- [Demo & Execution Plan](./DEMO_AND_EXECUTION_PLAN.md) — Initial 24-hour hackathon execution schedule and demo story.
- [OPFOR Comparison](./OPFOR_COMPARISON.md) — Competitive positioning against Agent OPFOR and strategic differentiation.
- [ADR 0001: Report Artifact Pipeline](./adr/0001-report-artifact-pipeline.md) — Immutable report architecture, canonical JSON, Markdown, and SARIF 2.1.0 projections.
- [Post-Hackathon Strategic Roadmap](./adr/POST_HACKATHON_ROADMAP.md) — Product evolution paths: reliability, developer experience/CI, and runtime policy SDK.
- [Prompt Specifications](./RAVEN_PROMPTS_SPEC.txt) — Core architectural prompts and system specifications.

## Repository Implementation Status

All core build artifacts and testing foundations have been implemented and verified:

- Root `README.md` with complete setup, architecture, and live demo walkthrough.
- Root `CLAUDE.md` reflecting monorepo structure and canonical contracts.
- `.env.example` template for configuration with zero leaked secrets.
- `LICENSE` (MIT) and `SECURITY.md` (vulnerability reporting and responsible AI use).
- Automated test suites: **149 passing tests** (73 in `apps/api`, 76 in `workers/evaluator`).
- `packages/attack-catalog/` with 12 versioned attack cases (A-01 to A-12) and 8 benign utility cases (B-01 to B-08).
- `packages/contracts/` with JSON schemas for scans, findings, reports, and SARIF 2.1.0.
- `fixtures/shophelper/` with simulated customer support target, synthetic customers, and canary tokens.
- Containerization: `infra/docker-compose.yml`, `infra/Dockerfile.api`, `infra/Dockerfile.worker`, `infra/Dockerfile.web`.

## Target Scope & Guardrails

RAVEN runs against the built-in local `ShopHelper` target as well as external HTTP endpoints configured with explicit authorization (validating URL schemes, blocking private/loopback/cloud-metadata IP ranges, and requiring `X-Raven-Scan-Consent: true`). It never executes destructive tools, never auto-deploys unreviewed changes, and adheres to strict execution budgets.

## Product Name

**RAVEN** stands for **Red-team Analysis, Verification, Enforcement, and Normal-use Assurance**.

One-line pitch:

> RAVEN attacks AI applications, proves their failures, generates enforceable guardrails, and verifies that security fixes preserve legitimate behavior.

See [RAVEN vs. Agent OPFOR](./OPFOR_COMPARISON.md) for competitive positioning and implementation priorities.
