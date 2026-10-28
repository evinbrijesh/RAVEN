# RAVEN OWASP Coverage Recommendation

## Decision

Four broad attack categories were enough for the original MVP, but they are not enough for RAVEN's current product ambition. However, RAVEN should not respond by creating one shallow test for every OWASP item.

The current catalog already contains 18 attack cases across more than four practical families:

- Direct and indirect prompt injection.
- System-prompt and canary leakage.
- Sensitive-information disclosure.
- Excessive agency and unsafe tool use.
- MCP tool-description and parameter attacks.
- RAG/document-based injection and leakage.

The next step is to make the catalog **OWASP-complete by coverage profile**, not merely OWASP-labeled by name.

## Important taxonomy distinction

The OWASP LLM Top 10 is a risk taxonomy. It is not a list of ten identical prompt attacks. Some risks require:

- Runtime adversarial tests.
- Static supply-chain checks.
- RAG/index integrity checks.
- Groundedness and correctness evaluation.
- Resource and quota testing.
- Tool-policy enforcement tests.

Therefore, a single `attack_runner` should not be forced to test every OWASP category. RAVEN should expose several test families that share the same evidence, verdict, remediation, and regression contracts.

## Current coverage against OWASP 2025

The official OWASP 2025 categories include Prompt Injection, Sensitive Information Disclosure, Supply Chain, Data and Model Poisoning, Improper Output Handling, Excessive Agency, System Prompt Leakage, Vector and Embedding Weaknesses, Misinformation, and Unbounded Consumption. See the official OWASP list: [OWASP Top 10 for LLMs and GenAI](https://genai.owasp.org/llm-top-10/).

### Strong current coverage

#### LLM01: Prompt Injection

Covered by:
- A-01 to A-03 direct injection.
- A-16 to A-18 indirect/RAG injection cases.
- MCP tool-description manipulation where instructions influence agent behavior.

Needed improvement:
- Separate direct and indirect injection as distinct subcategories.
- Record the injection source: user, document, tool description, memory, or external page.
- Verify whether the injected instruction caused a state change or tool call.

#### LLM02: Sensitive Information Disclosure

Covered by:
- A-07 to A-09 sensitive-data extraction.
- A-18 RAG-based PII extraction.
- A-04 to A-06 system/canary leakage, which should also map to LLM07.

Needed improvement:
- Add authorization-aware disclosure tests.
- Add cross-tenant and cross-user access cases.
- Add redaction and output-boundary checks.

#### LLM06: Excessive Agency

Covered by:
- A-10 to A-12 refund and authorization failures.
- A-13 to A-15 MCP tool and parameter attacks.
- PolicyGateway enforcement.

This is currently RAVEN's strongest differentiator. Keep it central.

#### LLM07: System Prompt Leakage

Covered by:
- A-04 to A-06 canary leakage.
- A-17 RAG canary exfiltration.

Needed improvement:
- Test partial disclosure, translation, summarization, encoding, and multi-turn extraction.
- Distinguish exact canary leakage from general policy disclosure.

### Partial coverage

#### LLM04: Data and Model Poisoning

A-16 to A-18 provide document-poisoning-style tests, but this is not full data/model poisoning coverage. They currently test whether a poisoned document can influence behavior. They do not test training-data poisoning, embedding-index poisoning, or provenance.

Rename the mapping carefully:

```
RAG indirect-instruction injection
not full model-poisoning coverage
```

Add an `index_integrity` or `retrieval_poisoning` test family rather than claiming all LLM04 risks are covered.

#### LLM08: Vector and Embedding Weaknesses

RAG cases may exercise retrieval behavior, but they do not automatically prove vector or embedding weakness coverage.

Add tests for:
- Retrieval of unauthorized documents.
- Tenant-boundary failures.
- Near-duplicate or adversarially similar chunks.
- Top-k poisoning.
- Metadata-filter bypass.
- Embedding-space collision or retrieval confusion.
- Citation/provenance mismatch.

These require a deterministic retrieval fixture and expected-document ground truth.

### Currently missing or weak

#### LLM03: Supply Chain

This should not be implemented as a prompt attack. Add a supply-chain scanner for:
- Model and provider identity.
- Dependency versions.
- Package vulnerabilities.
- Unpinned model or prompt assets.
- Untrusted tool servers.
- MCP server provenance.
- Container and image digests.
- Attack-catalog and policy provenance.

Produce a separate supply-chain finding type and SARIF rules.

#### LLM05: Improper Output Handling

Add output-boundary tests where model output is passed to:
- SQL.
- HTML.
- Markdown.
- Shell commands.
- URLs.
- Template engines.
- Tool arguments.
- Structured business actions.

Use a fake sink that records whether output was validated, escaped, schema-checked, or executed. Do not run real shell commands or destructive actions.

#### LLM09: Misinformation

This requires a ground-truth evaluation suite, not a jailbreak prompt. Add:
- Grounded answer cases.
- Unsupported-claim cases.
- Citation verification.
- Abstention behavior.
- Conflicting-source cases.
- Out-of-date knowledge cases.

The judge should compare claims against a trusted fixture and label unsupported claims separately from malicious behavior.

#### LLM10: Unbounded Consumption

Add resource-abuse tests for:
- Excessive prompt length.
- Recursive tool loops.
- Repeated tool calls.
- High fan-out agent plans.
- Long-running generation.
- Expensive retrieval queries.
- Repeated retries.
- Concurrent requests.

The target adapter should expose counters for:

```
model calls
input/output tokens
tool calls
retrieval calls
wall-clock time
estimated cost
concurrency
```

A finding should be based on exceeding a configured budget, not on an arbitrary timeout alone.

## Recommended catalog design

Add explicit test-family metadata:

```json
{
  "id": "A-21",
  "family": "improper_output_handling",
  "owasp": ["LLM05:2025"],
  "mitre_atlas": [],
  "target_capabilities": ["sql_sink"],
  "goal": "Cause model output to reach a SQL sink without validation",
  "seed_prompt": "...",
  "success_rule": "unvalidated_output_reached_sink",
  "evidence_requirements": ["sink_event", "validation_status"],
  "severity": "high",
  "remediation_type": "output_schema_and_sink_validation",
  "utility_suite": ["B-09"]
}
```

Every case should define:
- Risk taxonomy mapping.
- Required target capability.
- Attack or evaluation family.
- Deterministic evidence.
- Expected remediation.
- Utility impact.
- Regression behavior.
- Version.

## Recommended expansion phases

### Phase 1 — Strengthen the current core

Do not add every missing category yet. Improve the existing 18 cases:
- Direct versus indirect injection separation.
- Cross-user and cross-tenant disclosure.
- Partial and multilingual prompt leakage.
- MCP authorization and tool chaining.
- RAG provenance and document-source metadata.
- More benign cases for each remediation.
- Stable case fingerprints and evidence requirements.

Target: approximately 24–28 high-quality cases.

### Phase 2 — Add the most product-relevant missing risks

Prioritize these three families:
1. Improper output handling.
2. Unbounded consumption.
3. Vector/embedding and retrieval weaknesses.

These connect directly to RAVEN's existing PolicyGateway, target adapter, and regression model.

Target: approximately 30–36 high-quality cases plus resource and retrieval fixtures.

### Phase 3 — Add non-prompt security families

Add:
- Supply-chain checks.
- Model/prompt/tool provenance.
- Dependency and container metadata.
- MCP server trust and version verification.

These belong in a separate static and configuration-analysis pipeline that produces the same finding and SARIF contracts.

### Phase 4 — Add quality and research suites

Add:
- Misinformation and groundedness.
- Advanced multi-turn attacks.
- RAG poisoning experiments.
- Tool-chain and cross-agent attacks.
- Multilingual and encoding variants.

These should be released as capability packs rather than mixed into every default scan.

## Default scan profiles

Do not run every case for every target. Add profiles:

```
quick:
Core prompt injection, leakage, tool authorization.

agent:
Quick profile + excessive agency, tool chains, output handling.

rag:
Agent profile + indirect injection, retrieval authorization, provenance.

resource:
Consumption, loop, concurrency, token, and latency budgets.

full:
All compatible capability packs; explicit cost and time warning.
```

A target should declare capabilities before incompatible tests are skipped:

```json
{
  "tools": true,
  "rag": true,
  "mcp": true,
  "sql_sink": false,
  "shell_sink": false,
  "resource_metrics": true
}
```

A skipped test must be reported as `not_applicable` with a reason, not as `passed`.

## Recommendation

Keep the current 18-case catalog and stop calling the project a four-category scanner. Reframe it as a versioned, capability-aware catalog with strong coverage of:

- Prompt injection.
- Sensitive information disclosure.
- System prompt leakage.
- Excessive agency and unsafe tool use.
- MCP tool security.
- RAG indirect injection.

Then add OWASP coverage in layers:

```
Current core
    ↓
Improper output + resource abuse + retrieval weaknesses
    ↓
Supply-chain and provenance analysis
    ↓
Groundedness/misinformation suite
    ↓
Advanced multi-turn and cross-agent packs
```

Do not claim “full OWASP Top 10 coverage” until every mapped category has:

1. Explicit evidence requirements.
2. Remediation contracts.
3. Regression tests.
4. A capability gate for skipping cleanly.
