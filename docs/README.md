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
- [v1.0 Release Notes](./v1.0-RELEASE-NOTES.md) — Comprehensive v1.0 release notes, changelog, architecture highlights, and migration guide.
- [Post-Hackathon Execution Plan](./POST_HACKATHON_EXECUTION_PLAN.md) — Detailed 30-day post-hackathon execution track and deliverables across reliability, CI/CD, and runtime defense.
- [Post-Hackathon Strategic Roadmap](./adr/POST_HACKATHON_ROADMAP.md) — Product evolution paths: reliability, developer experience/CI, and runtime policy SDK.
- [OWASP Coverage Recommendation](./OWASP_COVERAGE_RECOMMENDATION.md) — Strategic roadmap to OWASP-complete coverage profile, capability-aware scan profiles, and multi-phase expansion.
- [Prompt Specifications](./RAVEN_PROMPTS_SPEC.txt) — Core architectural prompts and system specifications.

## Repository Implementation Status

All core build artifacts, v1.0 capabilities, and testing foundations have been implemented and verified:

- Root `README.md` with complete setup, architecture, threat matrix, MCP scanning guide, and live demo walkthrough.
- Root `CLAUDE.md` reflecting monorepo structure, verification guidelines, and canonical contracts.
- `.env.example` template for configuration with zero leaked secrets.
- `LICENSE` (MIT) and `SECURITY.md` (vulnerability reporting and responsible AI use).
- Automated test suites: **293+ passing tests** (93 in `apps/api`, 128 + 10 soak cycles in `workers/evaluator`, and 72 in `packages/raven-guard`).
- `packages/attack-catalog/` with 18 versioned attack cases (A-01 to A-18: Catalog v1 and v2) and 8 benign utility cases (B-01 to B-08).
- `packages/contracts/` with JSON schemas for scans, findings, reports, and SARIF 2.1.0.
- `packages/raven-guard/` fail-closed runtime policy gateway SDK with LangChain/LangGraph, FastAPI, and OpenTelemetry instrumentation.
- `workers/evaluator/evaluator/cli.py` (`raven-test`) standalone CLI runner with SARIF 2.1.0 output, dry-run profiling, and Unicode Frontier Scorecards.
- `.github/actions/raven-security-scan/` reusable composite GitHub Action for automated pull request security regression gates.
- `workers/evaluator/evaluator/targets/mcp_adapter.py` Model Context Protocol adapter for stdio, in-process, and SSE transports.
- `fixtures/shophelper/` with simulated customer support target, synthetic customers, and canary tokens.
- Containerization: `infra/docker-compose.yml`, `infra/Dockerfile.api`, `infra/Dockerfile.worker`, `infra/Dockerfile.web`.
- End-to-end verification and demonstration script: `scripts/demo_v1.py`.

## Target Scope & Guardrails

RAVEN runs against the built-in local `ShopHelper` target as well as external HTTP endpoints configured with explicit authorization (validating URL schemes, blocking private/loopback/cloud-metadata IP ranges, and requiring `X-Raven-Scan-Consent: true`). It never executes destructive tools, never auto-deploys unreviewed changes, and adheres to strict execution budgets.

## Product Name

**RAVEN** stands for **Red-team Analysis, Verification, Enforcement, and Normal-use Assurance**.

One-line pitch:

> RAVEN attacks AI applications, proves their failures, generates enforceable guardrails, and verifies that security fixes preserve legitimate behavior.

See [RAVEN vs. Agent OPFOR](./OPFOR_COMPARISON.md) for competitive positioning and implementation priorities.
