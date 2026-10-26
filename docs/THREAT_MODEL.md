# RAVEN Threat Model and Safety Plan

## 1. Security objective

RAVEN must help an authorized owner test an LLM application without becoming a tool for attacking unrelated systems, leaking secrets, or taking destructive actions.

## 2. Assets

- Target application configuration.
- System prompts and guardrails.
- Fake or real user data.
- Scan transcripts and findings.
- Model API keys.
- User authorization decisions.
- Hardening proposals.
- Audit records.

## 3. Threats and mitigations

| Threat | Risk | MVP control |
|---|---|---|
| Unauthorized target scanning | Abuse and legal exposure | Built-in target default; external HTTP targets require explicit `X-Raven-Scan-Consent: true` header |
| SSRF through target URL | Internal network access | Strict SSRF validator: scheme validation (http/https), DNS resolution, and blocking of private, loopback, link-local, multicast, and cloud metadata IPs |
| Prompt injection from target output | Agent behavior manipulation | Treat target output as data; fixed tool schemas; no instruction execution |
| Secret leakage to model | Confidentiality loss | Fake secrets only; redaction; reject obvious credentials |
| Tool misuse by target | Side effects | Simulated tool; fail-closed authorization policy |
| Model-generated unsafe hardening | Availability/security regression | Proposal-only output; approval; retest; rollback |
| Malicious attack-library content | Agent manipulation | Versioned, reviewed local attack cases |
| Unbounded attack loop | Cost/availability abuse | Count, time, concurrency, and token budgets |
| Judge hallucination | Incorrect finding | Deterministic checks first; disagreement becomes needs review |
| Transcript exposure | Privacy loss | Per-scan access control; redacted exports; deletion |
| Model provider outage | Incomplete scan | Partial-result state; deterministic fallback |
| False sense of security | Unsafe deployment | Mandatory limitations and coverage in every report |

## 4. Authorization and SSRF policy

### Built-in local target policy (`shophelper-local`)
```json
{
  "target_mode": "built_in_local",
  "network_access": false,
  "destructive_tools": false,
  "external_side_effects": false,
  "max_attack_cases": 12,
  "max_attempts_per_case": 2,
  "human_approval_required_for_hardening": true
}
```

### External HTTP target defense (`apps/api/app/security/ssrf.py`)
- **Scheme Validation**: Strictly allows only `http` and `https`.
- **IP & DNS Resolution Checks**: Resolves hostnames and rejects private IPv4/IPv6, loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10), multicast, and reserved ranges.
- **Cloud Metadata Shield**: Blocks cloud metadata endpoints (e.g. AWS/GCP `169.254.169.254`).
- **Consent Header Enforcement**: Enforces `X-Raven-Scan-Consent: true` on all external targets before scanning.
- **Budget Envelopes**: Request timeout, concurrency caps, retry limits, and total scan duration.

## 5. Prompt-injection defense

The target may attempt to manipulate the attacker, judge, or hardener through its output. Controls:

- Keep system instructions separate from target content.
- Wrap target output as quoted untrusted evidence.
- Use structured tool calls with allowlisted names and arguments.
- Do not let target output change scan policy.
- Do not let an LLM decide whether it is allowed to use a tool.
- Validate all model outputs with Pydantic schemas.
- Log instruction conflicts and judge disagreements.

## 6. Secure reporting language

Reports must include:

> RAVEN measures behavior against the selected test cases. A reduced attack success rate is not proof that the target is secure against unknown attacks.

Never use:

- Fully secure
- Guaranteed safe
- Zero vulnerabilities
- Complete protection
- Hacker-proof

Use:

- Confirmed under tested case
- Blocked in 2/2 trials
- Improvement observed under stated checks
- Needs review
- Coverage not evaluated

## 7. Data handling

- Use synthetic data for the hackathon.
- Do not commit API keys.
- Keep `.env` out of version control.
- Redact tokens from logs.
- Avoid sending raw transcripts to third-party observability systems unless explicitly configured.
- Delete scan data on request.
- Document model-provider data retention in production.

## 8. Security test checklist

- Can the target make the worker execute a shell command? It must not.
- Can a target output change the attack budget? It must not.
- Can the user select a private IP? Not in MVP.
- Can an invalid model response crash the scan? It must become `needs_review` or retry.
- Can a hardening proposal deploy automatically? It must not.
- Can a transcript expose the model API key? It must be redacted.
- Can a failed scan falsely appear passed? It must show incomplete/partial status.

## 9. Additional RAVEN-specific threats

### Over-refusal after hardening

A guardrail may block both malicious and legitimate requests. RAVEN mitigates this by requiring a benign utility suite and reporting utility regression separately.

### Policy overreach

A generated runtime rule may be broader than the finding requires. RAVEN limits policy scope, displays a diff, requires approval, and tests unrelated benign tasks before acceptance.

### Regression reopening failure

A previously fixed behavior may return after a model or prompt change. RAVEN stores confirmed findings as versioned regression cases and reopens them when the expected safe behavior fails.

### Evidence laundering

A model judge might summarize a failure without preserving the original proof. RAVEN keeps raw transcript references and deterministic rule outputs attached to every verdict.
