# 🦅 raven-test
### Autonomous Security Regression & Remediation Assurance CLI for LLM Applications

`raven-test` is the standalone developer CLI and CI/CD security gate from the **RAVEN** framework. It autonomously executes versioned red-team attack catalogs, validates 0% over-refusal against benign utility suites, generates human-in-the-loop prompt/policy hardening diffs, and outputs OASIS SARIF 2.1.0 logs for GitHub Code Scanning.

---

## ⚡ Quickstart

### 1. Installation

```bash
pip install raven-test
```

### 2. Scaffold a New Project

```bash
raven-test init
```

### 3. Pre-Flight Validation (Zero-Attack Dry Run)

```bash
raven-test run --dry-run
```

### 4. Run CI/CD Security Regression Scan

```bash
raven-test run --config raven.yaml --fail-on high --output sarif
```

---

## 🔒 Features

* **OWASP LLM & MITRE ATLAS Mapped:** Direct prompt injection, canary token extraction, tool misuse, and PII disclosure.
* **Frontier PR Scorecard:** Before vs. after Attack Success Rate (ASR) with risk reduction delta.
* **0% Over-Refusal Guarantee:** Runs utility regression tests to prove legitimate customer requests continue functioning.
* **Reviewable Hardening Diffs:** Emits unified diffs for system prompts and deterministic tool guardrails without silently auto-committing.
* **OASIS SARIF 2.1.0 & GitHub Action Native:** Integrates with GitHub Code Scanning alerts and pull request check annotations.
