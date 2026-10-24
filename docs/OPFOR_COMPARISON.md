# RAVEN vs. Agent OPFOR

**Date:** 2026-10-24  
**Purpose:** Decide whether RAVEN is still differentiated and define features that are defensible, useful, and feasible.

## Executive verdict

Agent OPFOR is a serious, mature overlap rather than a superficial competitor. Its public repository describes an open-source adversary-emulation toolkit for AI agents, LLM applications, and MCP servers. It already supports CLI, browser extension, MCP server, skills, and SDK entry points; multi-turn attacks; tools, memory, MCP, and agent behavior; OWASP-mapped suites; trace-aware judging; cost reporting; and reproducible HTML/JSON reports [1][2].

RAVEN should not compete by offering more attack prompts or more standards mappings. That would be a weaker copy of OPFOR. The better product wedge is:

> **RAVEN is a security regression and remediation assurance system: it proves what failed, proposes a constrained mitigation, checks whether normal behavior was preserved, and continuously verifies that the mitigation remains effective.**

This is a product-positioning conclusion, not a claim that OPFOR has no related features. RAVEN must test the actual implementation and document precise boundaries.

## What Agent OPFOR already does

| Capability | Agent OPFOR status | Consequence for RAVEN |
|---|---|---|
| Adversarial prompt generation | Core capability | Do not claim attack generation as novel. |
| Multi-turn attacks | Supported | Do not compete on multi-turn alone. |
| Agent, chatbot, HTTP, local-script targets | Supported | A local target is fine for the MVP, but is not differentiation. |
| MCP server red teaming | Supported | Do not claim MCP testing as a unique feature. |
| Tools, memory, and internal agent behavior | Explicitly targeted | RAVEN needs a different value proposition. |
| OWASP LLM, Agentic AI, MCP, API, MITRE ATLAS and bias suites | Broad documented coverage | Keep only a small mapping for credibility; do not market taxonomy breadth. |
| LLM-based judging | Supported | Deterministic evidence must be central to RAVEN. |
| Trace-aware testing | Langfuse and Netra integrations documented | Do not claim internal trace visibility as unique. |
| Browser extension | Supported | Avoid building a browser extension unless it directly serves a different workflow. |
| CLI, MCP, SDK, skills | Supported | RAVEN should initially be a focused workflow product, not an entry-point collection. |
| HTML/JSON reports | Supported | Reporting format is not a moat. |
| Severity-weighted score, ASR, cost tracking | Documented in releases and CLI docs | Do not use metrics alone as differentiation. |
| Autonomous hunt/adaptive attacks | Documented in project materials and releases | A simple mutation loop is not enough to differentiate. |

OPFOR's evaluator documentation describes YAML-based evaluators and suites, with agent and MCP evaluator trees, multi-turn attack patterns, and broad standards coverage [3]. Its CLI documentation also describes HTTP/local-script agent targets, MCP targets, attack generation, judging, reports, graceful interruption, and per-model testing cost [2].

## What RAVEN should own instead

### 1. Remediation assurance, not just vulnerability discovery

RAVEN should continue after OPFOR-style discovery. For every confirmed finding it should create a mitigation proposal, show a readable diff, apply the proposal only to a temporary evaluation target, and rerun the exact failed cases.

The result should not be “fixed.” It should be an evidence state such as:

- Attack blocked in 2/2 trials.
- Benign utility passed in 9/10 trials.
- No new policy violation observed in the selected suite.
- Verification is limited to the stated test cases.

The important distinction is the **remediation contract**: every proposed fix has to be tested against both security and normal behavior.

### 2. Utility-preserving hardening

RAVEN should measure whether a hardening change causes over-refusal or breaks legitimate workflows. Define a utility suite with task-specific expected outcomes rather than generic “safe” prompts.

Example:

```text
Security test:
Do not issue a refund without verified order details.

Benign test:
Explain the refund policy for order 1001.

Utility test:
After the customer provides valid order details, prepare a simulated refund.
```

This allows RAVEN to show a security/utility frontier rather than a single safety score. A mitigation that blocks all requests is not a good product outcome.

### 3. Deterministic evidence ledger

OPFOR documents attack prompts, responses, judge verdicts, traces, and reports. RAVEN should go further by storing the evidence chain behind each verdict:

```text
Finding
  → attack case version
  → target version/configuration
  → exact request/response transcript
  → deterministic rule outputs
  → model-judge output
  → hardening proposal version
  → retest results
  → benign utility results
```

The differentiator is not “we log transcripts.” It is that every conclusion is reproducible and every disagreement remains visible. RAVEN should never let an LLM judge override an exact canary leak or unauthorized tool call.

### 4. Guardrail regression over time

OPFOR is primarily a scan-and-report workflow. RAVEN should be designed around a persistent regression set:

- A finding becomes a saved security test.
- The test runs on every prompt, model, tool, system-prompt, or guardrail change.
- A previously fixed case can reopen.
- The system identifies which change caused the regression.
- The report shows security and utility trends over time.

This changes the product from “a red-team scanner” to “CI for AI behavior.” That is the strongest long-term positioning.

### 5. Policy and approval engine

RAVEN should make the hardening decision explicit:

```text
Finding confirmed
       ↓
Mitigation proposed
       ↓
Security/utility impact estimated
       ↓
Human approval required
       ↓
Temporary evaluation
       ↓
Merge/deploy recommendation
```

The MVP does not need production deployment. It should create a deployable artifact only after approval and successful retesting. Future policy rules can include:

- Never auto-approve prompt changes that alter allowed tools.
- Block deployment if a critical tool-misuse case remains.
- Require human review when security and utility metrics disagree.
- Reject a fix when the model judge disagrees with deterministic evidence.

### 6. Runtime guardrail verification

RAVEN can add a second product mode after the MVP: a proxy or SDK wrapper that checks tool calls and sensitive outputs at runtime. The red-team findings become runtime policies.

Example:

```text
Discovered finding:
Refund tool can be called without order verification.

Generated runtime policy:
Allow issue_refund only when:
- verified_order_id exists;
- user identity is verified;
- refund amount is below the configured threshold;
- approval is present for high-value refunds.
```

This creates a closed loop that OPFOR’s discovery-oriented workflow does not appear to center in the documented materials:

```text
Discover → Explain → Generate policy → Enforce at runtime → Regression-test
```

Do not claim that OPFOR cannot do this unless you verify its current source and documentation. Say that RAVEN is productized around this workflow.

## Recommended repositioning

### Weak positioning

> An automated LLM red-teaming platform that generates attacks and reports vulnerabilities.

This overlaps heavily with OPFOR.

### Strong positioning

> RAVEN converts AI red-team findings into tested guardrail policies and continuously verifies that fixes improve security without breaking legitimate behavior.

### Strongest hackathon claim

> OPFOR-style tools help discover that an AI application fails. RAVEN demonstrates whether a proposed fix actually reduces the failure, preserves normal utility, and remains protected in future changes.

This is a comparison statement about product focus, not a claim that OPFOR lacks every related feature.

## Revised MVP: RAVEN Assurance Loop

Keep the controlled ShopHelper target, but change the demo around **fix verification** rather than attack breadth.

### MVP attack suite

Use 8–12 cases across four categories:

- Canary/system-prompt disclosure.
- Direct prompt injection.
- Sensitive-data extraction.
- Unauthorized simulated tool call.

### MVP utility suite

Use 8–10 legitimate tasks:

- Order lookup.
- Refund-policy explanation.
- Validated refund preparation.
- Shipping-status explanation.
- Account-help request.

### MVP hardening outputs

Generate two possible artifacts:

1. A proposed system-prompt diff.
2. A machine-readable runtime policy for the simulated `issue_refund` tool.

For the hackathon, the runtime policy can be enforced by a local policy gateway rather than a general-purpose proxy.

### MVP report

The report should show:

- Confirmed findings and exact evidence.
- Before/after attack success rate.
- Benign utility score before/after.
- Over-refusal cases.
- Hardening diff.
- Runtime policy diff.
- Reopened/regressed cases.
- Cost, latency, and test coverage.
- Explicit limitations.

## What not to build

Do not try to beat OPFOR on the following during a 24-hour hackathon:

- More OWASP categories.
- More attack templates.
- A browser extension.
- An MCP server mode.
- A large CLI/SDK ecosystem.
- 60 attack cases.
- A general-purpose external target crawler.
- A larger standards matrix.
- A generic HTML report.

These features increase surface area without creating a defensible reason to choose RAVEN.

## Proposed differentiation score

| Dimension | RAVEN focus | Score potential |
|---|---|---:|
| Attack breadth | Intentionally narrow | 2/5 |
| Evidence quality | Deterministic plus provenance chain | 5/5 |
| Remediation | Tested prompt and policy changes | 5/5 |
| Utility preservation | Explicit benign regression suite | 5/5 |
| Continuous regression | Saved tests and reopen logic | 5/5 |
| Runtime enforcement | Policy gateway for tool calls | 4/5 |
| Hackathon feasibility | One local target and bounded suite | 5/5 |
| Product distinction from OPFOR | Assurance/control-plane focus | 4/5 |

## Licensing and reuse

The Agent OPFOR repository is published under Apache License 2.0 according to its public LICENSE file [4]. If you reuse code, evaluator definitions, or datasets, preserve required notices, identify modifications, and check all transitive dependency and dataset licenses before distribution. For the hackathon, it is safer to use OPFOR as a conceptual baseline or optional adapter and implement RAVEN’s evidence, hardening, policy, and regression layers independently.

## Final recommendation

Do not abandon RAVEN because Agent OPFOR exists. Abandon the idea only if you plan to build another general red-team scanner.

Build RAVEN as the layer that comes after scanning:

```text
Red-team finding
      ↓
Evidence normalization
      ↓
Constrained hardening proposal
      ↓
Runtime policy candidate
      ↓
Human approval
      ↓
Security retest
      ↓
Benign utility retest
      ↓
Persistent regression test
```

That is more production-oriented, more defensible, and more aligned with the stated preference for a rare, real-world-ready system than simply adding another attack library.

## References

[1]: https://github.com/KeyValueSoftwareSystems/agent-opfor "Agent OPFOR repository overview"
[2]: https://github.com/KeyValueSoftwareSystems/agent-opfor/blob/master/docs/cli.md "Agent OPFOR CLI documentation"
[3]: https://github.com/KeyValueSoftwareSystems/agent-opfor/blob/master/docs/evaluators.md "Agent OPFOR evaluator and suite documentation"
[4]: https://github.com/KeyValueSoftwareSystems/agent-opfor/blob/master/LICENSE "Agent OPFOR Apache License 2.0"
[5]: https://github.com/KeyValueSoftwareSystems/agent-opfor/releases "Agent OPFOR releases and changelog"
