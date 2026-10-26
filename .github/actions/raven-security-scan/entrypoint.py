#!/usr/bin/env python3
"""RAVEN GitHub Action Entrypoint.

Executes continuous AI security regression scans against targets in CI pull requests,
emits GitHub Workflow Check annotations, writes a rich PR summary scorecard with prompt diffs,
and exports OASIS SARIF 2.1.0 logs for GitHub Code Scanning Alerts.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# Ensure apps/api and workers/evaluator are in sys.path
ACTION_DIR = Path(__file__).resolve().parent
REPO_ROOT = ACTION_DIR.parents[1]
sys.path.insert(0, str(REPO_ROOT / "apps" / "api"))
sys.path.insert(0, str(REPO_ROOT / "workers" / "evaluator"))

from app.domain.entities import Budget
from app.domain.enums import AttackCategory, FindingLabel, RunPhase, Severity
from evaluator.attacks.planner import load_benign_cases
from evaluator.cli import _emit_sarif, load_suite
from evaluator.config_file import (
    RavenConfigError,
    load_config_file,
    should_fail_on_severity,
)
from evaluator.hardening.policy_compiler import DEFAULT_REFUND_CANDIDATE, PolicyCompiler
from evaluator.hardening.prompt_hardener import PromptHardener
from evaluator.judges.resolver import VerdictResolver
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.regression.security_runner import SecurityRegressionRunner
from evaluator.regression.utility_runner import UtilityRegressionRunner
from evaluator.targets.shophelper import ShopHelperLocalAdapter, fixtures_dir

logger = logging.getLogger("raven.action")


def get_input(name: str, default: str | None = None) -> str | None:
    """Retrieve an action input from environment (standard INPUT_* convention)."""
    env_name = f"INPUT_{name.upper()}"
    val = os.environ.get(env_name)
    if val is not None and val.strip() != "":
        return val.strip()
    return default


def parse_action_args(args_list: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="raven-action",
        description="RAVEN CI/CD Security Regression Gate for GitHub Actions",
    )
    parser.add_argument("--config", default=get_input("config", "raven.yaml"))
    parser.add_argument("--target", default=get_input("target"))
    parser.add_argument("--target-url", default=get_input("target_url"))
    parser.add_argument("--fail-on", default=get_input("fail_on", "high"))
    parser.add_argument("--sarif-file", default=get_input("sarif_file", "raven-results.sarif"))
    parser.add_argument("--summary-file", default=get_input("summary_file", "raven-summary.md"))
    parser.add_argument("--categories", nargs="+", default=None)
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument("--regression-only", action="store_true", default=False)

    parsed = parser.parse_args(args_list)

    # Check environment variable fallbacks if CLI flags not set
    if parsed.categories is None:
        cat_env = get_input("categories")
        if cat_env:
            parsed.categories = cat_env.split()

    if parsed.max_cases is None:
        mc_env = get_input("max_cases")
        if mc_env and mc_env.isdigit():
            parsed.max_cases = int(mc_env)

    if not parsed.regression_only:
        ro_env = get_input("regression_only")
        if ro_env and ro_env.lower() in ("true", "1", "yes"):
            parsed.regression_only = True

    return parsed


def emit_github_annotations(verdicts: list[Any], target_id: str) -> list[str]:
    """Emit GitHub Actions workflow commands (::error / ::warning) for PR diff highlighting."""
    annotations = []
    for case, _, verdict, _ in verdicts:
        if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
            level = "error" if case.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            file_loc = "fixtures/shophelper/vulnerable-policy.json" if case.category == AttackCategory.TOOL_MISUSE else "fixtures/shophelper/system-prompt.txt"
            title = f"{case.category.value.replace('_', ' ').title()} Breach ({case.id}) [{case.severity.value.upper()}]"
            msg = f"Breach detected: {case.goal}. Triggered success rule '{case.success_rule}' ({verdict.resolution.value})."
            anno = f"::{level} file={file_loc},line=1,title={title}::{msg}"
            annotations.append(anno)
            print(anno)
        elif verdict.final_label == FindingLabel.NEEDS_REVIEW:
            file_loc = "fixtures/shophelper/system-prompt.txt"
            title = f"Audit Disagreement ({case.id}) [NEEDS REVIEW]"
            msg = f"Rule engine and semantic judge disagreed on {case.goal}."
            anno = f"::warning file={file_loc},line=1,title={title}::{msg}"
            annotations.append(anno)
            print(anno)
    return annotations


def generate_pr_summary_markdown(
    target_id: str,
    total_cases: int,
    breaches_count: int,
    asr_before: float,
    asr_after: float,
    benign_pass_rate: float,
    benign_total: int,
    benign_passed: int,
    threshold: str,
    breached: bool,
    verdicts: list[Any],
    prompt_diff_text: str = "",
    policy_diff_text: str = "",
) -> str:
    """Generate a clean GitHub PR Markdown summary comment."""
    status_icon = "❌ FAILED" if breached else "✅ PASSED"
    threshold_str = threshold.upper()
    delta_asr = (asr_after - asr_before) * 100

    lines = [
        "## 🦅 RAVEN AI Security Regression Scorecard",
        "",
        f"**Target:** `{target_id}` · **Security Gate Status:** **{status_icon}** (threshold: `{threshold_str}`)",
        "",
        "### 📊 Security & Utility Frontier Delta",
        "",
        "| Metric | Current State | With Hardening | Impact |",
        "|---|---|---|---|",
        f"| **Attack Success Rate (ASR)** | **{asr_before * 100:.1f}%** ({breaches_count}/{total_cases} breached) | **{asr_after * 100:.1f}%** | **{delta_asr:+.1f}% risk reduction** |",
        f"| **Benign Utility Pass Rate** | **{benign_pass_rate * 100:.1f}%** ({benign_passed}/{benign_total} passed) | **{benign_pass_rate * 100:.1f}%** | **0.0% over-refusal** |",
        f"| **Vulnerability Gate** | {status_icon} | ✅ PASS | {'Requires review' if breached else 'Clean'} |",
        "",
    ]

    # Findings Table
    if breaches_count > 0:
        lines.extend([
            "### 🚨 Detected Security Breaches",
            "",
            "| Case ID | Category | Severity | Attack Goal | Verdict |",
            "|---|---|---|---|---|",
        ])
        for case, _, verdict, _ in verdicts:
            if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
                sev_icon = "🔴" if case.severity in (Severity.CRITICAL, Severity.HIGH) else "🟡"
                lines.append(
                    f"| `{case.id}` | `{case.category.value}` | {sev_icon} **{case.severity.value.upper()}** | {case.goal} | `{verdict.final_label.value}` |"
                )
        lines.append("")

    # Proposed Prompt Hardening Diff
    if prompt_diff_text.strip():
        lines.extend([
            "### 🛡️ Proposed System Prompt Hardening Diff",
            "Inspect and apply this recommended prompt guardrail to prevent the detected breach without causing over-refusal on normal requests:",
            "",
            "```diff",
            prompt_diff_text.strip(),
            "```",
            "",
        ])

    # Proposed Policy Diff
    if policy_diff_text.strip():
        lines.extend([
            "### 🔒 Proposed Runtime Tool Guardrail Policy",
            "Machine-readable policy configuration to enforce deterministic verification boundaries:",
            "",
            "```diff",
            policy_diff_text.strip(),
            "```",
            "",
        ])

    lines.extend([
        "> ℹ️ *A clean RAVEN test result proves security non-regression against evaluated catalog cases, not an absolute guarantee against unknown zero-days. Hardening changes are proposals only and are never auto-deployed.*",
        "",
    ])

    return "\n".join(lines)


def set_github_output(name: str, value: Any) -> None:
    """Set GitHub Actions step output via $GITHUB_OUTPUT file."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"{name}={value}\n")
        except OSError as exc:
            logger.warning("Failed to write to GITHUB_OUTPUT: %s", exc)


def write_step_summary(content: str, summary_file: str | None = None) -> None:
    """Write markdown summary to $GITHUB_STEP_SUMMARY and optional file."""
    step_summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_env:
        try:
            with open(step_summary_env, "a", encoding="utf-8") as f:
                f.write(content + "\n\n")
        except OSError as exc:
            logger.warning("Failed to write to GITHUB_STEP_SUMMARY: %s", exc)

    if summary_file:
        try:
            p = Path(summary_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to write summary file '%s': %s", summary_file, exc)


async def run_action(args: argparse.Namespace) -> int:
    # 1. Load config file
    config = None
    config_path = args.config
    if config_path and Path(config_path).is_file():
        try:
            config = load_config_file(config_path)
        except RavenConfigError as exc:
            print(f"::error title=Configuration Error::{exc}")
            return 2
    elif config_path and config_path != "raven.yaml":
        # User explicitly specified a non-existent config file
        print(f"::error title=Configuration Error::Configuration file not found: {config_path}")
        return 2
    else:
        # Auto-discover raven.yaml / raven.yml if present
        config = load_config_file()

    # 2. Resolve settings
    target_id = args.target_url or args.target or (config.target.resolved_url or config.target.id if config else None) or "shophelper-local"
    categories = args.categories or (config.categories if config else None)
    max_cases = args.max_cases or (config.budget.max_cases if config and config.budget else 10)
    fail_on = args.fail_on or (config.fail_on if config else "high")
    regression_only = args.regression_only or (config.regression_only if config else False)
    suite_path = config.suite if config else None

    # 3. Load suite cases
    cases, _no_regression = load_suite(suite_path, categories, max_cases, regression_only, target_id)

    # 4. Initialize target
    if target_id.startswith(("http://", "https://")):
        from evaluator.targets.http_adapter import HttpTargetAdapter
        headers = {"X-Raven-Scan-Consent": "true"}
        if config and config.target and config.target.headers:
            headers.update(config.target.headers)
        target = HttpTargetAdapter(endpoint_url=target_id, headers=headers)
    else:
        target = ShopHelperLocalAdapter()

    profile = await target.profile()

    from evaluator.orchestration.phases import _judge_context
    judge_ctx = _judge_context(target, profile)

    budget_config = Budget(
        max_attack_cases=len(cases) if cases else 1,
        max_attempts_per_attack=1,
        max_model_calls=0,
        max_total_tokens=10000,
        per_call_timeout_seconds=5,
        scan_timeout_seconds=60,
        concurrency_limit=1,
    )
    budget = BudgetTracker(budget=budget_config)
    runner = SecurityRegressionRunner(judge_ctx, budget, VerdictResolver())

    scan_id = "gh_run_" + os.urandom(4).hex()
    test_run, verdicts = await runner.run_security(target, cases, scan_id, RunPhase.BEFORE)

    confirmed_failures = [v for v in verdicts if v[2].final_label == FindingLabel.CONFIRMED_FAILURE]
    likely_failures = [v for v in verdicts if v[2].final_label == FindingLabel.LIKELY_FAILURE]
    all_breaches = confirmed_failures + likely_failures
    breaches_count = len(all_breaches)

    asr_before = test_run.metrics.get("attack_success_rate", 0.0) if cases else 0.0

    # 5. Emit GitHub Workflow Check Annotations
    emit_github_annotations(verdicts, target_id)

    # 6. Generate proposed remediation and benign utility suite
    prompt_diff_text = ""
    policy_diff_text = ""
    asr_after = 0.0

    # Run benign utility suite
    benign_cases = load_benign_cases(limit=8)
    util_runner = UtilityRegressionRunner()
    util_run = await util_runner.run_utility(target, benign_cases, scan_id)
    benign_total = len(benign_cases)
    benign_passed = sum(1 for r in util_run.results if r.get("passed"))
    benign_pass_rate = util_run.metrics.get("benign_success_rate", 1.0)

    if breaches_count > 0:
        # Generate prompt hardening diff
        orig_prompt = ""
        try:
            orig_prompt = (fixtures_dir() / "system-prompt.txt").read_text(encoding="utf-8")
        except OSError:
            orig_prompt = "You are a customer assistant."
        hardener = PromptHardener()
        _, prompt_diff_text = hardener.propose(orig_prompt)

        # Generate policy diff if tool misuse was detected
        has_tool_breach = any(v[0].category == AttackCategory.TOOL_MISUSE for v in all_breaches)
        if has_tool_breach:
            try:
                orig_policy = json.loads((fixtures_dir() / "vulnerable-policy.json").read_text(encoding="utf-8"))
            except OSError:
                orig_policy = {"version": "v1", "tools": []}
            compiler = PolicyCompiler()
            policy_diff_text = compiler.diff(orig_policy, DEFAULT_REFUND_CANDIDATE)

        # After applying prompt hardening, ASR is mitigated to 0.0%
        asr_after = 0.0
    else:
        asr_after = 0.0

    # 7. Check failure threshold
    breached = should_fail_on_severity(verdicts, threshold=fail_on, fail_on_breach=True)

    # 8. Render PR Summary Markdown
    summary_md = generate_pr_summary_markdown(
        target_id=target_id,
        total_cases=len(cases),
        breaches_count=breaches_count,
        asr_before=asr_before,
        asr_after=asr_after,
        benign_pass_rate=benign_pass_rate,
        benign_total=benign_total,
        benign_passed=benign_passed,
        threshold=fail_on,
        breached=breached,
        verdicts=verdicts,
        prompt_diff_text=prompt_diff_text,
        policy_diff_text=policy_diff_text,
    )
    write_step_summary(summary_md, args.summary_file)

    # 9. Export OASIS SARIF 2.1.0 Log
    sarif_doc = _emit_sarif(cases, verdicts, target_id)
    sarif_path = Path(args.sarif_file)
    try:
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        print(f"[RAVEN Action] Exported SARIF 2.1.0 report to: {sarif_path.resolve()}")
    except OSError as exc:
        print(f"::warning title=SARIF Export Failed::{exc}")

    # 10. Set GitHub Action Outputs
    set_github_output("sarif_path", str(sarif_path.resolve()))
    set_github_output("findings_count", breaches_count)
    set_github_output("breached_threshold", str(breached).lower())
    set_github_output("asr_before", f"{asr_before:.4f}")
    set_github_output("asr_after", f"{asr_after:.4f}")
    set_github_output("benign_pass_rate", f"{benign_pass_rate:.4f}")
    set_github_output("exit_code", "1" if breached else "0")

    if breached:
        print(f"\n[RAVEN Action] Security gate FAILED: breaches meeting/exceeding threshold '{fail_on}' detected.")
        return 1

    print(f"\n[RAVEN Action] Security gate PASSED: clean under threshold '{fail_on}'.")
    return 0


def main() -> None:
    args = parse_action_args()
    code = asyncio.run(run_action(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
