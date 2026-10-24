# RAVEN Documentation Pack

RAVEN is an agentic security regression system for LLM applications. It attacks a controlled target, verifies findings, proposes hardening, and retests security and normal behavior.

## Documents

- [PRD](./PRD.md) — product vision, MVP scope, requirements, metrics, backlog, and business model.
- [Data Flow](./DATA_FLOW.md) — inputs, processing stages, trust boundaries, data classification, events, retention, and failure paths.
- [Architecture](./ARCHITECTURE.md) — components, state machine, agent responsibilities, schemas, and implementation order.
- [Threat Model](./THREAT_MODEL.md) — assets, threats, safety controls, authorization policy, and security test checklist.
- [Claude Instructions](./CLAUDE.md) — coding-agent context, non-negotiable safety rules, project structure, and definition of done.
- [API Contract](./API_CONTRACT.md) — endpoint behavior, request/response schemas, status conventions, and errors.
- [Demo and Execution Plan](./DEMO_AND_EXECUTION_PLAN.md) — live demo, 24-hour schedule, team split, pitch, and Q&A.

## Required build artifacts not yet included

These should be created in the implementation repository:

- `README.md` with setup and demo instructions.
- `.env.example` with no real secrets.
- `docker-compose.yml` only if external services are actually required.
- `LICENSE` after confirming dependency licenses.
- `SECURITY.md` with responsible-use and vulnerability-reporting guidance.
- `CONTRIBUTING.md` if accepting external contributions.
- `CHANGELOG.md` for release notes.
- `tests/` with deterministic judge and state-machine tests.
- `fixtures/` with synthetic ShopHelper data.
- `docs/attack-library.md` with reviewed attack-case definitions.
- `docs/model-policy.md` documenting model providers, retention, and cost limits.

## Naming note

“RAVEN” is a working name. It can be changed before implementation without affecting the architecture or requirements.

## MVP boundary

The MVP runs only against the built-in local ShopHelper target. It does not scan arbitrary third-party endpoints, execute real side effects, or claim that a reduced attack success rate proves security.

## Product name

**RAVEN** means **Red-team Analysis, Verification, Enforcement, and Normal-use Assurance**.

RAVEN is deliberately positioned relative to Agent OPFOR. OPFOR is an important broad adversary-emulation baseline. RAVEN does not try to win through attack-library breadth. It focuses on turning findings into constrained hardening proposals, runtime policies, and persistent regression tests while measuring legitimate utility.

One-line pitch:

> RAVEN attacks AI applications, proves their failures, generates enforceable guardrails, and verifies that security fixes preserve legitimate behavior.

See [RAVEN vs. Agent OPFOR](./OPFOR_COMPARISON.md) for the competitive positioning and implementation priorities.
