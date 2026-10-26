# 🦅 RAVEN GitHub Action: Autonomous AI Security Gate

Continuous AI security regression testing and remediation assurance for LLM applications and agent backends in GitHub Actions.

## Quickstart

Add `.github/workflows/raven-security.yml` to your repository:

```yaml
name: "RAVEN AI Security Gate"
on:
  pull_request:
    branches: [ "main" ]

jobs:
  ai-security-scan:
    name: "Red-Team & Regression Gate"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run RAVEN Security Scan
        uses: ./.github/actions/raven-security-scan
        with:
          config: "raven.yaml"
          fail_on: "high"
          sarif_file: "raven-results.sarif"

      - name: Upload Results to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "raven-results.sarif"
```

## Features

1. **Automated Breach Detection:** Executes versioned attack catalogs against local or external HTTP endpoints.
2. **GitHub Workflow Annotations:** Emits native `::error` annotations directly onto vulnerable prompt/policy files in the PR diff.
3. **PR Summary Scorecard:** Writes a rich Markdown table into `$GITHUB_STEP_SUMMARY` comparing Attack Success Rate (ASR) before vs. after.
4. **Utility Preservation Verification:** Runs a benign utility suite to prove 0.0% over-refusal on legitimate business requests.
5. **Unified Diff Previews:** Displays recommended system prompt diffs and tool guardrails directly on the pull request.
6. **OASIS SARIF 2.1.0 Export:** Ingests findings into repository Code Scanning Alerts.

## Action Inputs

| Input | Description | Default |
|---|---|---|
| `config` | Path to declarative `raven.yaml` file | `raven.yaml` |
| `target` | Target adapter or ID (`shophelper-local` or HTTP URL) | `shophelper-local` |
| `target_url` | Direct HTTP endpoint URL for external targets | `""` |
| `fail_on` | Severity threshold to block PR (`critical`, `high`, `medium`, `low`, `none`) | `high` |
| `sarif_file` | Output path for OASIS SARIF 2.1.0 log | `raven-results.sarif` |
| `summary_file` | Output path for Markdown summary | `raven-summary.md` |
| `categories` | Space-separated attack categories filter | `""` |
| `max_cases` | Maximum attack test cases to run | `10` |
| `regression_only` | Replay only active promoted regression cases | `false` |

## Action Outputs

| Output | Description |
|---|---|
| `sarif_path` | Absolute path to generated SARIF 2.1.0 file |
| `findings_count` | Number of confirmed/likely security breaches detected |
| `breached_threshold` | Whether severity threshold was crossed (`true` / `false`) |
| `asr_before` | Attack Success Rate before remediation |
| `asr_after` | Attack Success Rate after proposed remediation |
| `benign_pass_rate` | Benign utility pass rate (proving 0% over-refusal) |
| `exit_code` | Process exit code (`0` for clean, `1` for failure) |
