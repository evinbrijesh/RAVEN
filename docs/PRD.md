# RAVEN Product Requirements Document

**Status:** Hackathon-ready draft  
**Working name:** RAVEN  
**Track:** AI for Cybersecurity  
**Version:** 0.1  
**Target build:** 24-hour, two-person hackathon MVP

## 1. Product summary

RAVEN is an agentic security regression system for LLM applications. It evaluates an LLM app against bounded attack cases, verifies failures using deterministic evidence checks and a structured AI judge, proposes constrained hardening changes, and re-tests the target against both attacks and benign prompts.

The original product vision is a continuous security assurance platform:

> Attack, verify, harden, and re-test LLM applications before attackers do.

The hackathon MVP is intentionally narrower: one locally hosted vulnerable customer-support bot, four attack categories, deterministic evidence checks, one bounded mutation attempt, one hardening proposal, and a before/after comparison.

RAVEN must never claim that passing its test set proves an application is secure. It reports security behavior under stated checks and exposes coverage limits.

## 2. Problem

Teams are deploying support bots, RAG systems, and tool-using AI agents without a repeatable way to test prompt injection, secret leakage, sensitive-data disclosure, and unsafe tool use. Manual testing is inconsistent and existing red-team tools are often difficult for small teams to operationalize. A useful product must do more than generate attacks: it must provide evidence, propose a mitigation, check for over-refusal, and preserve an audit trail.

## 3. Goals

### MVP goals

1. Let a user create a scan against an authorized target.
2. Use a local demo target as the default and safest path.
3. Run a bounded attack suite across four categories.
4. Use deterministic checks before model-based judging.
5. Record complete transcripts and structured verdicts.
6. Generate a readable hardening proposal with a diff.
7. Re-run successful attacks after hardening.
8. Run benign prompts to measure utility regression.
9. Show before/after metrics and evidence.
10. Produce a downloadable JSON or Markdown report.

### Product goals after the hackathon

- Support HTTP target adapters with explicit authorization.
- Support CI execution and SARIF output.
- Support repository-specific regression suites.
- Support RAG/document injection tests.
- Support multiple target providers and model gateways.
- Support organization policies, scan history, and trend analysis.
- Support human approval and versioned guardrail deployment.

## 4. Non-goals for the MVP

- Scanning arbitrary public websites or third-party systems.
- Real-world destructive tool actions.
- Fully autonomous production prompt or guardrail deployment.
- Claiming formal security guarantees.
- 40–60 attack cases; the MVP uses approximately 12 carefully designed cases.
- A multi-agent swarm.
- Full MITRE ATLAS coverage.
- Complete PDF, SARIF, GitHub, Slack, and SIEM integrations.
- Arbitrary browser or web crawling.

## 5. Target users

### Primary user

A startup developer, AI engineer, or security-minded product team shipping an LLM application without a dedicated AI security team.

### Secondary users

- Application-security engineers
- Red-team consultants
- AI platform teams
- Compliance and governance teams
- Hackathon judges evaluating measurable technical depth

## 6. MVP target application

RAVEN ships with a local demo bot named **ShopHelper**. It has:

- A system prompt containing a fake canary token.
- Fake customer information.
- A simulated `issue_refund` tool.
- A policy requiring order verification before refunds.
- A small set of normal customer-support tasks.

The tool must be simulated and must not cause real refunds, messages, payments, or external side effects.

## 7. User stories

- As an AI developer, I want to scan my LLM app against known attack cases so that I can see where it fails.
- As a security reviewer, I want every finding to include the transcript and rule that produced it.
- As a developer, I want a proposed hardening change rather than only a vulnerability label.
- As a product owner, I want to know whether the mitigation blocks normal users.
- As a reviewer, I want the system to show uncertainty when deterministic and model judges disagree.
- As a user, I want to scan only targets I own or have permission to test.

## 8. Functional requirements

### FR-1: Scan creation

The user can select the built-in ShopHelper target, choose an attack suite, configure a scan budget, and start a scan.

### FR-2: Target authorization

The MVP only executes against the local built-in target. Future HTTP targets require explicit authorization, an allowlist, private-network blocking, rate limits, timeouts, and a consent header.

### FR-3: Reconnaissance

The recon step sends a small number of harmless probes and produces a structured target profile. The profile may include supported task type, refusal behavior, tool availability, and canary-test capability.

### FR-4: Attack library

Each attack is stored with an ID, category, goal, prompt, expected behavior, success rule, severity, and references. MVP categories:

- Direct prompt injection
- System-prompt/canary leakage
- Sensitive-data extraction
- Unauthorized tool use

### FR-5: Bounded mutation

A failed attack may receive one model-generated variant. The scan stops after the configured attempt limit.

### FR-6: Execution

The executor runs attacks with concurrency, timeout, retry, and budget limits. Every request and response is logged with redaction applied to sensitive fields.

### FR-7: Deterministic judging

The first judge checks canary tokens, known fake secrets, PII patterns, tool-call permissions, and expected refusal behavior.

### FR-8: LLM judging

The second judge receives only the necessary transcript and a fixed rubric. It returns structured JSON. It must not override a deterministic confirmed failure. Disagreement produces `needs_review`.

### FR-9: Hardening proposal

The hardener creates a proposed system-prompt or guardrail diff, a rationale, affected attack IDs, and expected trade-offs. It must not silently apply changes.

### FR-10: Regression testing

The system reruns the attack cases that failed before hardening and runs a fixed benign suite. It reports security improvement and utility regression separately.

### FR-11: Reporting

The report contains scan metadata, target profile, attack results, evidence transcripts, before/after metrics, hardening diff, benign-test results, tool/model versions, and limitations.

### FR-12: Failure handling

The UI must show loading, timeout, model failure, invalid response, budget exhaustion, target failure, and needs-review states. The system must fail closed for unsafe simulated tool actions.

## 9. Success metrics

### Hackathon metrics

- A complete scan runs without an unhandled crash.
- At least 8 of 12 attack cases produce deterministic or reviewable results.
- At least one canary-leak or unsafe-tool-use finding is reproduced.
- The hardening proposal reduces known attack success in the demo.
- At least 90% of benign prompts remain usable in the demo suite.
- Every displayed finding links to evidence.

### Product metrics

- Attack success rate by category.
- Confirmed-failure precision.
- Judge-disagreement rate.
- Hardening acceptance rate.
- Residual known-attack rate.
- Benign-task success rate.
- Over-refusal rate.
- Cost and latency per scan.
- Regression rate after hardening.

## 10. Result vocabulary

Use these labels instead of a simplistic vulnerable/fixed model:

- `confirmed_failure`
- `likely_failure`
- `attack_blocked`
- `needs_review`
- `partial_mitigation`
- `regression_detected`
- `not_evaluated`
- `verified_under_stated_checks`

## 11. Safety and privacy requirements

- Scan only built-in or explicitly authorized targets.
- Never send real secrets or personal data to the model.
- Use fake canaries and fake customer data in the demo.
- Block private IP ranges for future HTTP targets.
- Apply request timeouts and concurrency caps.
- Do not allow real-world destructive tool calls.
- Redact credentials and tokens in logs and reports.
- Keep model-generated changes in a proposal state until approval.
- Make limitations visible in the report.

## 12. Acceptance criteria

The MVP is ready for judging when a fresh user can:

1. Open the application.
2. Start a scan against ShopHelper.
3. See live progress.
4. Observe a confirmed attack result with transcript evidence.
5. Review the proposed hardening diff.
6. Approve the simulated hardening step.
7. See the attack re-tested.
8. See benign prompts tested.
9. Compare before/after metrics.
10. Export a report.

## 13. Prioritized backlog

### P0

- ShopHelper target
- Scan state machine
- 12 attack cases
- Deterministic judge
- Structured LLM judge
- Hardening proposal
- Before/after re-test
- Benign regression suite
- Report screen
- Error and timeout states

### P1

- One mutation per failed attack
- Scan history
- Markdown/JSON export
- OWASP category tags
- Cost and latency display
- Simple prompt/guardrail diff viewer

### P2

- HTTP target connector
- SARIF export
- CI action
- RAG indirect-injection mode
- GitHub integration
- Organization policy management

## 14. Business model

Possible future pricing:

- Free local scan for individuals.
- Usage-based scans for small teams.
- CI-gate subscription for startups.
- Self-hosted enterprise edition for sensitive deployments.

The moat is not the LLM alone. It is the attack/regression corpus, customer-specific tests, historical trend data, evidence provenance, and safe hardening workflow.

## 15. Positioning relative to Agent OPFOR

Agent OPFOR already provides broad adversary emulation for AI agents, LLM applications, and MCP servers, including multi-turn attacks, OWASP-mapped suites, trace-aware judging, CLI/browser/MCP/SDK entry points, and reproducible reports. RAVEN must not claim novelty for attack generation, multi-turn testing, MCP testing, OWASP mapping, or generic red-team reporting.

RAVEN is positioned as the layer that comes after discovery. Its differentiating workflow is:

```text
Red-team finding → evidence ledger → constrained hardening proposal
→ runtime policy candidate → human approval → security retest
→ benign utility retest → persistent regression test
```

The product claim is therefore not “RAVEN finds more attacks than OPFOR.” It is “RAVEN turns findings into tested, reviewable mitigations and keeps them as regression tests.”

## 16. RAVEN product principles

1. **Assurance over breadth:** a small number of reproducible, evidence-backed checks is more valuable than a large unverified attack catalog.
2. **Security and utility together:** a mitigation is incomplete if it prevents legitimate workflows.
3. **Policy is explicit:** discovered failures can produce runtime policy candidates, but policies require approval and testing.
4. **Findings become tests:** every confirmed issue can be saved as a regression case.
5. **Uncertainty is visible:** disagreement, incomplete coverage, and untested behavior must remain visible.
6. **No security theater:** RAVEN reports improvement under stated checks, never universal security.
