# RAVEN Demo and 24-Hour Execution Plan

## 1. Live demo story

### Opening

“LLM applications can fail in ways normal unit tests do not cover. RAVEN attacks a controlled AI application, proves the failures with evidence, proposes a bounded mitigation, and checks whether the mitigation breaks normal use.”

### Demo sequence

1. Open ShopHelper and ask a normal order-status question.
2. Show the scan configuration and authorization state.
3. Start the scan.
4. Show live attack progress.
5. Display a confirmed canary leak.
6. Display an unauthorized simulated refund tool call.
7. Open the transcript and deterministic evidence.
8. Show the hardening proposal diff.
9. Approve the temporary hardening configuration.
10. Re-run the failed cases.
11. Run benign prompts.
12. Show before/after metrics and limitations.

### Target final result

```text
Before:
- 4 confirmed/likely failures out of 12 cases
- 1 unsafe tool call
- 1 canary disclosure

After:
- 1 needs-review result
- 0 unsafe tool calls in 2/2 trials
- 10/10 benign prompts passed

Statement:
Improved under the evaluated cases; not a proof of security.
```

## 2. 24-hour plan

### Hours 0–2: foundation

- Create repository and commit history.
- Define schemas and statuses.
- Build ShopHelper target.
- Create fixtures and reset script.

### Hours 2–6: deterministic core

- Attack case format.
- Target executor.
- Canary/secret/PII checks.
- Tool-policy check.
- SQLite or in-memory scan state.

### Hours 6–10: orchestrator

- State machine.
- Bounded retries and budgets.
- Event stream.
- Partial-failure handling.

### Hours 10–13: model layer

- Structured attacker variant.
- Structured LLM judge.
- Schema validation.
- Timeout and invalid-JSON handling.

### Hours 13–16: hardening and regression

- Hardening proposal.
- Approval screen.
- Temporary hardened target.
- Before/after attack run.
- Benign suite.

### Hours 16–20: UI and report

- Scan form.
- Live feed.
- Findings table.
- Transcript viewer.
- Diff viewer.
- Metrics cards.
- Export report.

### Hours 20–22: reliability

- Test model failure.
- Test target timeout.
- Test invalid input.
- Test empty results.
- Test disagreement state.
- Add demo reset and fallback fixtures.

### Hours 22–24: pitch

- Freeze features.
- Run the demo repeatedly.
- Record backup video.
- Prepare architecture slide.
- Prepare threat model and limitations.
- Prepare business model and Q&A answers.

## 3. Team split

### Developer

- ShopHelper target.
- Orchestrator and state model.
- Executor and judges.
- Hardening and retest.
- API and integration.

### Design/documentation partner

- UI flows and visual system.
- Attack-case content and OWASP mapping.
- Report layout.
- Test fixtures and demo script.
- README, pitch, business model, and Q&A.

The second person should still contribute test cases, acceptance checks, and structured content rather than only preparing slides.

## 4. Judge questions and answers

### How is this different from promptfoo, garak, or PyRIT?

Those tools establish important baselines for probing and evaluation. RAVEN focuses on a bounded closed loop: evidence-backed findings, proposed hardening, before/after retesting, and benign-utility regression reporting.

### Does a low attack success rate prove safety?

No. It only describes the selected test suite and configuration. RAVEN makes that limitation explicit.

### Why use deterministic checks?

Exact canary leaks and unauthorized tool calls should not depend on an LLM opinion. The model judge is used only for semantic cases.

### Why not fully automate the fix?

An unreviewed prompt or guardrail change can introduce over-refusal or new behavior. RAVEN proposes a change, tests it, and requires approval.

### Who would pay?

Startups and product teams shipping AI features could pay for per-scan usage or CI-gate access. Larger organizations may prefer self-hosting because transcripts and prompts can be sensitive.

### What is the moat?

Customer-specific regression suites, longitudinal scan results, evidence provenance, safe hardening workflows, and measured patch/guardrail outcomes—not merely the use of an LLM.

## 5. Pitch structure

1. Problem: ordinary tests do not test LLM-specific attack behavior.
2. Demo: ShopHelper fails in two concrete ways.
3. Product: RAVEN attacks, verifies, hardens, and retests.
4. Technical depth: bounded agent, deterministic judge, LLM judge, approval, regression suite.
5. Result: before/after security and utility metrics.
6. Business: developer/security teams need repeatable AI assurance.
7. Honesty: measured coverage is not proof of safety.
8. Ask: integrate with CI and customer-specific AI regression suites.

## 6. Differentiation demo against broad red-team tools

Do not present RAVEN as a larger attack scanner. Explicitly demonstrate the product step that follows an OPFOR-style finding:

1. RAVEN identifies an unsafe refund-tool call.
2. It displays the exact transcript and deterministic policy violation.
3. It generates a runtime policy candidate requiring order and user verification.
4. A human approves the temporary policy.
5. The attack is blocked in repeated trials.
6. Legitimate refund-policy and verified-refund tasks still pass.
7. The confirmed finding is saved as a persistent regression test.

The judge should leave with one clear distinction: RAVEN does not stop at “your agent failed”; it shows whether the proposed mitigation is effective and usable.
