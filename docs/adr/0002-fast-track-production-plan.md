# ADR 0002: Accelerated 28-Day Production Execution Plan

- **Status:** Accepted
- **Date:** 2026-10-26
- **Supersedes:** 90-Day General Roadmap in `POST_HACKATHON_ROADMAP.md`
- **Full Specification Document:** [`docs/POST_HACKATHON_EXECUTION_PLAN.md`](../POST_HACKATHON_EXECUTION_PLAN.md)

---

## Context & Decision

The initial roadmap (`POST_HACKATHON_ROADMAP.md`) scoped out a standard 90-day enterprise timeline. With dedicated, daily hands-on engineering, we are committing to an aggressive **28-Day (4-Week) High-Velocity Sprint** to convert RAVEN from a hackathon prototype into a deployable, open-core developer platform.

### Core Strategic Focus

Instead of diffusing engineering focus across arbitrary targets and dozens of model providers, we are doubling down on our high-conviction wedge:

> **Continuous security regression testing and runtime policy enforcement for tool-using AI agents.**

### 4-Week Sprint Schedule

1. **Week 1 (Days 1–7): Zero-Technical-Debt Baseline & Bulletproof Reliability**
   - SQLite-backed state checkpointing and restart-safe worker execution.
   - Idempotent graph nodes (preventing duplicate findings or runs).
   - Sensitive data redaction and cryptographic run hashes.
   - Automated end-to-end integration and contract tests.

2. **Week 2 (Days 8–14): Developer-First CI/CD & GitHub Action Wedge**
   - Polished, standalone `raven-test` CLI with rich terminal diff rendering.
   - Declarative `raven.yaml` project configuration.
   - Official GitHub Action (`actions/raven-security-scan`) with PR annotations and SARIF 2.1.0 upload.
   - Gating on high-severity regressions and utility drop.

3. **Week 3 (Days 15–21): Standalone Runtime PolicyGateway SDK (`raven-guard`)**
   - Package extraction of the PolicyGateway into a standalone PyPI package (`raven-guard`).
   - Zero-overhead, fail-closed runtime tool authorization engine.
   - Native Python decorators and LangChain/LangGraph middlewares (`@gateway.protect`).
   - Financial limits, parameter validation, and structured audit logs.

4. **Week 4 (Days 22–28): MCP Integration & Advanced Threat Suite**
   - Model Context Protocol (MCP) target adapter (evaluating tool descriptions, schema injection, confused deputy attacks).
   - Indirect prompt injection and RAG document poisoning test cases.
   - Final packaging, documentation, and public v1.0.0 release.

---

For daily checklists, task-by-task engineering breakdowns, and success gates, see the comprehensive [Accelerated 28-Day Execution Plan](../POST_HACKATHON_EXECUTION_PLAN.md).
