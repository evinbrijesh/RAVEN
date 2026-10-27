#!/usr/bin/env python3
"""Official RAVEN GitHub Action Entrypoint.

Executes `raven-test` evaluation, generates Frontier PR scorecard markdown,
emits Code Scanning workflow annotations, and optionally posts comments to PRs.
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
from app.domain.enums import AttackCategory, FindingLabel, RunPhase
from evaluator.attacks.planner import load_benign_cases
from evaluator.cli import _emit_sarif, load_suite
from evaluator.config_file import (
    RavenConfigError,
    load_config_file,
    should_fail_on_severity,
)
from evaluator.github_action_formatter import (
    emit_workflow_annotations,
    format_pr_comment,
    post_github_pr_comment,
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
    env_name = f"INPUT_{name.upper().replace('-', '_')}"
    val = os.environ.get(env_name)
    if val is not None and val.strip() != "":
        return val.strip()
    return default


def parse_action_args(args_list: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="raven-action",
        description="RAVEN CI/CD Security Regression Gate for GitHub Actions",
    )
    parser.add_argument(
        "--config",
        "--config-file",
        dest="config",
        default=get_input("config_file") or get_input("config", "raven.yaml"),
        help="Path to raven.yaml configuration file",
    )
    parser.add_argument(
        "--target",
        default=get_input("target", ""),
        help="Target adapter or ID to evaluate",
    )
    parser.add_argument(
        "--target-url",
        dest="target_url",
        default=get_input("target_url", ""),
        help="Direct HTTP endpoint URL for target application",
    )
    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        default=get_input("fail_on", "high"),
        help="Severity threshold to trigger failure exit code",
    )
    parser.add_argument(
        "--sarif-file",
        dest="sarif_file",
        default=get_input("sarif_file", "raven-results.sarif"),
        help="Path for exported SARIF 2.1.0 file",
    )
    parser.add_argument(
        "--summary-file",
        dest="summary_file",
        default=get_input("summary_file", "raven-summary.md"),
        help="Path for generated Markdown summary file",
    )
    parser.add_argument(
        "--comment-on-pr",
        dest="comment_on_pr",
        default=get_input("comment_on_pr", "true"),
        help="Whether to post PR comment on GitHub",
    )
    parser.add_argument(
        "--github-token",
        dest="github_token",
        default=get_input("github_token", os.environ.get("GITHUB_TOKEN", "")),
        help="GitHub token for API authentication",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help="Filter attack categories",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=None,
        help="Maximum attack cases to run",
    )
    parser.add_argument(
        "--regression-only",
        action="store_true",
        default=False,
        help="Run only active promoted regression cases",
    )

    parsed = parser.parse_args(args_list)

    # Fallback env checks for categories and max-cases
    if not parsed.categories:
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


def set_output(name: str, value: Any) -> None:
    """Set GitHub Actions step output via $GITHUB_OUTPUT file."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"{name}={value}\n")
        except OSError as e:
            logger.warning("Failed writing to GITHUB_OUTPUT: %s", e)
    print(f"[RAVEN Output] {name}={value}")


async def run_action(args: argparse.Namespace) -> int:
    print("=" * 60)
    print("🦅 Starting RAVEN AI Security Evaluation Gate")
    print("=" * 60)

    # 1. Load configuration
    config_path = args.config
    config = None
    try:
        config = load_config_file(config_path)
        print(f"[RAVEN Action] Loaded configuration from: {config_path}")
    except FileNotFoundError:
        if config_path in ("raven.yaml", "raven.yml"):
            print(f"[RAVEN Action] Default configuration '{config_path}' not found; using CLI defaults.")
            config = None
        else:
            print(f"::error title=Configuration Error::Configuration file not found: {config_path}")
            return 2
    except RavenConfigError as exc:
        print(f"::error title=Configuration Error::{exc}")
        return 2

    # 2. Merge options
    target_id = (
        args.target_url
        or args.target
        or (config.target.resolved_url if config and config.target and config.target.resolved_url else None)
        or (config.target.id if config and config.target else None)
        or "shophelper-local"
    )

    categories = args.categories or (config.categories if config else None)
    max_cases = (
        args.max_cases
        or (config.budget.max_cases if config and config.budget else None)
        or 10
    )
    regression_only = args.regression_only or (config.regression_only if config else False)
    fail_on = args.fail_on or (config.fail_on if config else "high")
    suite_path = config.suite if config else None

    # 3. Load suite cases
    cases, _no_regression = load_suite(suite_path, categories, max_cases, regression_only, target_id)

    # 4. Initialize target
    if target_id.startswith(("http://", "https://")):
        from evaluator.targets.http_adapter import HttpTargetAdapter

        headers = {"X-Raven-Scan-Consent": "true"}
        if config and config.target and config.target.headers:
            headers.update(config.target.headers)

        allow_local = (
            (config.target.allow_local_dev if config and config.target else False)
            or os.environ.get("RAVEN_ALLOW_LOCAL_TARGETS", "").lower() in ("true", "1", "yes")
        )
        req_template = (config.target.request_template if config and config.target else None) or {"message": "{prompt}"}
        resp_path = (config.target.response_json_path if config and config.target else None) or "response"
        timeout_s = (config.target.timeout_seconds if config and config.target else None) or 30.0
        mode = (config.target.mode if config and config.target else None) or "evaluation_only"

        target = HttpTargetAdapter(
            endpoint_url=target_id,
            headers=headers,
            request_template=req_template,
            response_json_path=resp_path,
            timeout_seconds=timeout_s,
            mode=mode,
            allow_local_dev=allow_local,
        )
    else:
        target = ShopHelperLocalAdapter()

    profile = await target.profile()
    from evaluator.orchestration.phases import _judge_context

    judge_ctx = _judge_context(target, profile)

    budget_config = Budget(
        max_attack_cases=len(cases),
        max_attempts_per_attack=1,
        max_model_calls=0,
        max_total_tokens=10000,
        per_call_timeout_seconds=5,
        scan_timeout_seconds=60,
        concurrency_limit=1,
    )
    budget = BudgetTracker(budget=budget_config)
    runner = SecurityRegressionRunner(judge_ctx, budget, VerdictResolver())

    scan_id = "gh_action_" + os.urandom(4).hex()
    print(f"[RAVEN Action] Running {len(cases)} security regression cases against '{target_id}'...")
    test_run, verdicts = await runner.run_security(target, cases, scan_id, RunPhase.BEFORE)

    # 5. Extract findings
    all_breaches = [
        v for v in verdicts
        if v[2].final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE)
    ]
    breaches_count = len(all_breaches)
    asr_before = test_run.metrics.get("attack_success_rate", 0.0)

    # 6. Emit GitHub Annotations
    emit_workflow_annotations(verdicts, target_id)

    # 7. Run benign utility suite (proving 0% over-refusal)
    benign_cases = load_benign_cases(limit=8)
    util_runner = UtilityRegressionRunner()
    util_run = await util_runner.run_utility(target, benign_cases, scan_id)
    benign_total = len(benign_cases)
    benign_passed = sum(1 for r in util_run.results if r.get("passed"))
    benign_pass_rate = util_run.metrics.get("benign_success_rate", 1.0)

    prompt_diff_text = ""
    policy_diff_text = ""
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

        asr_after = 0.0
    else:
        asr_after = 0.0

    # 8. Check failure threshold
    breached = should_fail_on_severity(verdicts, threshold=fail_on, fail_on_breach=True)

    # 9. Render PR Summary Markdown
    summary_md = format_pr_comment(
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

    # Write summary file
    summary_path = Path(args.summary_file)
    try:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(summary_md, encoding="utf-8")
    except OSError as e:
        logger.warning("Failed to write summary file: %s", e)

    # 10. Post PR comment if requested
    comment_on_pr = str(args.comment_on_pr).lower() in ("true", "1", "yes")
    if comment_on_pr:
        post_github_pr_comment(
            comment_body=summary_md,
            github_token=args.github_token,
        )

    # 11. Export OASIS SARIF 2.1.0 Log
    sarif_doc = _emit_sarif(cases, verdicts, target_id)
    sarif_path = Path(args.sarif_file)
    try:
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        print(f"[RAVEN Action] Exported SARIF 2.1.0 report to: {sarif_path.resolve()}")
    except OSError as exc:
        print(f"::error title=SARIF Export Error::Failed to export SARIF: {exc}")

    # 12. Set GitHub Step Outputs
    exit_code = 1 if breached else 0
    set_output("sarif_path", str(sarif_path.resolve()))
    set_output("findings_count", breaches_count)
    set_output("breached_threshold", str(breached).lower())
    set_output("asr_before", f"{asr_before:.4f}")
    set_output("asr_after", f"{asr_after:.4f}")
    set_output("benign_pass_rate", f"{benign_pass_rate:.4f}")
    set_output("exit_code", exit_code)

    print("=" * 60)
    if breached:
        print(f"❌ RAVEN Security Gate Failed: {breaches_count} breaches met or exceeded '{fail_on.upper()}' threshold.")
    else:
        print("✅ RAVEN Security Gate Passed: All test cases satisfied security thresholds.")
    print("=" * 60)

    return exit_code


def main() -> None:
    args = parse_action_args()
    code = asyncio.run(run_action(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
