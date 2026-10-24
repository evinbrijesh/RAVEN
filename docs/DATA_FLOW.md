# RAVEN Data-Flow Document

**Version:** 0.1  
**Scope:** Hackathon MVP and production extension

## 1. High-level flow

```text
User
  │ scan configuration and authorization
  ▼
Web UI
  │ HTTPS/SSE
  ▼
FastAPI API
  │ creates scan and validates configuration
  ▼
Orchestrator / State Machine
  │
  ├── Recon worker
  ├── Attack planner
  ├── Target adapter ───────► ShopHelper local target
  ├── Deterministic judge
  ├── LLM judge
  ├── Hardener
  └── Regression runner
  │
  ▼
Evidence store + report generator
  │
  ├── Live progress to UI
  ├── JSON/Markdown report
  └── Optional future SARIF/CI output
```

## 2. Trust boundaries

### Boundary A: User to API

Untrusted user input enters through scan configuration, uploaded content, prompts, and future target URLs. Validate schemas, size, allowed values, and authorization.

### Boundary B: Orchestrator to target

The target may return adversarial or malformed content. Treat all target output as untrusted data. Never execute instructions found in target output.

### Boundary C: Orchestrator to model provider

Prompts may contain code, logs, and target output. Apply redaction, context limits, model allowlists, and cost limits. Do not send real credentials.

### Boundary D: Agent to tools

Tools are capability boundaries. The MVP exposes only simulated, read-only, or local tools. Every future tool requires an explicit permission policy.

### Boundary E: Evidence store to report

Reports may contain sensitive transcripts. Redact canaries only when necessary for external sharing, preserve the original evidence internally, and provide export controls.

## 3. Canonical scan state

```json
{
  "scan_id": "scan_123",
  "status": "testing_after_hardening",
  "target_id": "shophelper-local",
  "authorization": "built_in_target",
  "budget": {
    "max_attacks": 12,
    "max_attempts_per_attack": 2,
    "max_model_calls": 80,
    "timeout_seconds": 300
  },
  "phase": "regression",
  "progress": 0.72,
  "findings": [],
  "hardening_proposal_id": "fix_123"
}
```

## 4. Attack data flow

1. The attack library loads a bounded set of approved YAML/JSON cases.
2. The planner selects cases compatible with the target profile.
3. The executor sends a prompt to the target adapter.
4. The target response is stored as a transcript.
5. The deterministic judge evaluates the response and any simulated tool call.
6. If required, the LLM judge receives a minimized transcript.
7. The verdict is stored with evidence references.
8. The UI receives a progress event.

```text
Attack case → planner → executor → target → transcript → rule judge
                                                     └→ LLM judge
                                                               ↓
                                                           verdict
```

## 5. Hardening data flow

```text
Confirmed findings
        ↓
Hardener prompt with finding evidence
        ↓
Proposed prompt/guardrail diff
        ↓
Human approval in UI
        ↓
Temporary hardened target configuration
        ↓
Attack retest + benign regression suite
        ↓
Comparison report
```

The hardener never writes to a production target in the MVP. It creates a temporary target configuration used only for evaluation.

## 6. Data classification

| Data | Classification | MVP handling |
|---|---|---|
| Fake canary | Demo secret | Store locally; redact in external exports if needed |
| Fake customer data | Demo data | Store locally |
| User prompts | Potentially sensitive | Do not persist longer than scan retention requires |
| Target transcripts | Potentially sensitive | Store per scan; export only with confirmation |
| Model prompts | Sensitive operational data | Log metadata; avoid raw logging by default |
| Model responses | Potentially adversarial | Treat as untrusted; store for evidence |
| Scan metrics | Internal/project data | Store with scan |
| Future real credentials | Restricted | Reject in demo and redact before model calls |

## 7. Event model

```json
{
  "event_id": "evt_001",
  "scan_id": "scan_123",
  "type": "attack_verdict_created",
  "timestamp": "2026-10-24T20:00:00Z",
  "phase": "judge",
  "payload_ref": "verdict_456",
  "actor": "system",
  "severity": "high"
}
```

Event types:

- `scan_created`
- `recon_completed`
- `attack_started`
- `target_response_received`
- `deterministic_verdict_created`
- `llm_verdict_created`
- `judge_disagreement`
- `hardening_proposed`
- `hardening_approved`
- `regression_started`
- `scan_completed`
- `scan_failed`

## 8. Data retention

MVP default:

- Keep scan metadata and results for the current session.
- Keep transcripts until the user deletes the scan.
- Do not retain raw uploaded data beyond the scan lifecycle.
- Never include model API keys in application logs.

Production options:

- Configurable retention period.
- Tenant-isolated storage.
- Encryption at rest and in transit.
- Customer-managed keys for enterprise deployments.
- Audit log retention separate from transcript retention.

## 9. Output flow

The report generator consumes:

- Scan metadata
- Target profile
- Attack cases
- Transcripts
- Rule verdicts
- LLM verdicts
- Hardening diff
- Retest results
- Benign-test results
- Tool/model versions

It produces:

- Human-readable summary
- Evidence table
- Before/after metrics
- Limitations
- JSON machine-readable result
- Future SARIF finding output

## 10. Failure paths

- Target timeout → mark attack `not_evaluated`, continue if budget permits.
- Model timeout → use deterministic result and mark LLM judgment unavailable.
- Invalid model JSON → retry once, then mark `needs_review`.
- Judge disagreement → never auto-resolve; show both results.
- Hardening proposal invalid → reject proposal and preserve original result.
- Benign regression detected → mark `regression_detected`; do not claim improvement.
- Budget exhausted → finish with partial-results label.

## 11. RAVEN remediation and regression flow

```text
Confirmed finding
       ↓
Evidence bundle
       ↓
Prompt hardening diff + runtime policy candidate
       ↓
Human approval
       ↓
Temporary policy gateway
       ↓
Original attack retest
       ↓
Benign utility retest
       ↓
Save as versioned regression test
```

The evidence bundle is the product boundary between detection and assurance. It must include the attack-case version, target configuration, transcript, deterministic signals, semantic judge output, proposed changes, approval event, retest results, and limitations.
