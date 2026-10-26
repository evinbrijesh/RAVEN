"""RAVEN Standalone CI/CD Regression Runner CLI (`raven-test`).

Executes saved security regression test suites or curated attack catalogs
directly against a target adapter without requiring the full Web UI or API server.
Exits 0 if all tests pass (or no security regressions are detected),
or 1 if an attack successfully breaches or causes a confirmed failure meeting
the configured severity threshold.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from app.domain.entities import AttackCase, Budget
from app.domain.enums import FindingLabel, RunPhase, Severity
from app.infrastructure.db.repository import Repositories
from app.infrastructure.db.sqlite import Database
from pydantic import ValidationError

from evaluator.attacks.planner import load_attack_cases
from evaluator.config import get_worker_settings
from evaluator.config_file import (
    RavenConfigError,
    load_config_file,
    should_fail_on_severity,
)
from evaluator.judges.resolver import VerdictResolver
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.regression.security_runner import SecurityRegressionRunner
from evaluator.targets.shophelper import ShopHelperLocalAdapter

logger = logging.getLogger("raven.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raven-test",
        description="RAVEN Autonomous CI/CD Security Regression Gate",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=None,
        help="Path to raven.yaml configuration file (auto-detects raven.yaml or raven.yml if omitted)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target adapter or ID to execute against (default: shophelper-local)",
    )
    parser.add_argument(
        "--target-url",
        default=None,
        help="Direct endpoint URL for external HTTP target",
    )
    parser.add_argument(
        "--regression-only",
        action="store_true",
        default=None,
        help="Replay only active promoted regression cases for the target",
    )
    parser.add_argument(
        "--suite",
        default=None,
        help="Path to custom regression suite JSON file (default: loads from attack catalog)",
    )
    parser.add_argument(
        "--output",
        choices=["json", "sarif", "junit", "text"],
        default=None,
        help="Output format for regression test results (default: text)",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help="Filter attack categories (direct_injection, canary_leakage, sensitive_data, tool_misuse)",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=None,
        help="Maximum attack cases to run (default: 10)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default=None,
        help="Minimum severity threshold to trigger failure exit code (default: high)",
    )
    parser.add_argument(
        "--fail-on-breach",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Exit with non-zero exit code if any confirmed breach occurs (default: True)",
    )
    return parser


def load_suite(
    path: str | None,
    categories: list[str] | None,
    limit: int,
    regression_only: bool,
    target_id: str,
) -> tuple[list[AttackCase], bool]:
    """Returns (cases, is_empty_regression_suite)."""
    if regression_only:
        settings = get_worker_settings()
        db = Database(settings.database_path)
        db.migrate()
        repos = Repositories(db)
        active_rows = repos.regressions.list_active(target_id)
        if not active_rows:
            return [], True
        cases = []
        for row in active_rows:
            try:
                cases.append(AttackCase.model_validate_json(row["case_json"]))
            except (ValidationError, ValueError, KeyError) as exc:
                print(f"[RAVEN CI] skipping invalid regression row: {exc}", file=sys.stderr)
                continue
        if categories:
            cases = [c for c in cases if c.category.value in categories]
        return cases[:limit], False

    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Suite file not found: {path}")
        raw = json.loads(p.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("attack_cases", raw.get("cases", []))
        cases = [AttackCase.model_validate(c) for c in items]
        if categories:
            cases = [c for c in cases if c.category.value in categories]
        return cases[:limit], False

    return load_attack_cases(categories, limit=limit), False


def _emit_sarif(cases: list[AttackCase], verdicts: list, target_id: str) -> dict:
    rule_map = {
        "direct_injection": "RAVEN/LLM01-prompt-injection",
        "canary_leakage": "RAVEN/LLM07-system-prompt-leakage",
        "sensitive_data": "RAVEN/LLM06-sensitive-information-disclosure",
        "tool_misuse": "RAVEN/LLM08-excessive-agency",
    }
    rules = [
        {"id": rid, "shortDescription": {"text": cat.replace("_", " ")}}
        for cat, rid in rule_map.items()
    ]
    results = []
    for case, _, verdict, _ in verdicts:
        if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
            rule_id = rule_map.get(case.category.value, "RAVEN/SEC-GENERAL")
            level = "error" if case.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"Breach detected: {case.goal} ({case.id})"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"target://{target_id}"}}}],
                "properties": {
                    "attack_case_id": case.id,
                    "version": case.version,
                    "resolution": verdict.resolution.value,
                },
            })
    return {
        "$schema": "https://json.sarif.org/schema/2.1.0/sarif-schema.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "RAVEN", "rules": rules}},
                "results": results,
            }
        ],
    }


async def run_cli(args: argparse.Namespace) -> int:
    # 1. Load declarative configuration file (if present or specified)
    try:
        config = load_config_file(getattr(args, "config", None))
    except (FileNotFoundError, RavenConfigError) as exc:
        print(f"[RAVEN CI Error] {exc}", file=sys.stderr)
        return 2

    # 2. Merge target settings
    target_arg = getattr(args, "target", None)
    target_url_arg = getattr(args, "target_url", None)

    if target_url_arg:
        target_id = target_url_arg
        target_url = target_url_arg
        target_adapter = "http"
    elif target_arg:
        target_id = target_arg
        if target_arg.startswith(("http://", "https://")):
            target_url = target_arg
            target_adapter = "http"
        else:
            target_url = None
            target_adapter = target_arg
    elif config and config.target:
        target_id = config.target.id
        target_url = config.target.resolved_url
        target_adapter = config.target.adapter
    else:
        target_id = "shophelper-local"
        target_url = None
        target_adapter = "shophelper-local"

    # 3. Merge suite & category settings
    regression_only_arg = getattr(args, "regression_only", None)
    if regression_only_arg is not None:
        regression_only = bool(regression_only_arg)
    elif config:
        regression_only = config.regression_only
    else:
        regression_only = False

    categories_arg = getattr(args, "categories", None)
    if categories_arg is not None:
        categories = categories_arg
    elif config and config.categories:
        categories = config.categories
    else:
        categories = None

    suite_arg = getattr(args, "suite", None)
    if suite_arg is not None:
        suite_path = suite_arg
    elif config and config.suite:
        suite_path = config.suite
    else:
        suite_path = None

    max_cases_arg = getattr(args, "max_cases", None)
    if max_cases_arg is not None:
        max_cases = max_cases_arg
    elif config and config.budget and config.budget.max_cases:
        max_cases = config.budget.max_cases
    else:
        max_cases = 10

    # 4. Merge output & failure threshold settings
    output_arg = getattr(args, "output", None)
    if output_arg is not None:
        output_format = output_arg
    elif config and config.output:
        output_format = config.output
    else:
        output_format = "text"

    fail_on_arg = getattr(args, "fail_on", None)
    if fail_on_arg is not None:
        fail_on_threshold = fail_on_arg
    elif config and config.fail_on:
        fail_on_threshold = config.fail_on
    else:
        fail_on_threshold = "high"

    fail_on_breach_arg = getattr(args, "fail_on_breach", None)
    if fail_on_breach_arg is not None:
        fail_on_breach = bool(fail_on_breach_arg)
    elif config is not None:
        fail_on_breach = config.fail_on_breach
    else:
        fail_on_breach = True

    # 5. Load test cases
    cases, no_regression_cases = load_suite(
        suite_path, categories, max_cases, regression_only, target_id
    )

    if no_regression_cases:
        if output_format == "json":
            print(json.dumps({
                "target": target_id,
                "status": "no_regression_cases",
                "message": f"No active regression cases registered for target '{target_id}'.",
                "total_cases": 0,
            }, indent=2))
        elif output_format == "sarif":
            print(json.dumps(_emit_sarif([], [], target_id), indent=2))
        else:
            print(f"[RAVEN CI] No active regression cases registered for target '{target_id}'.", file=sys.stderr)
        return 0

    if not cases:
        print("[RAVEN CI] No attack test cases found to execute.", file=sys.stderr)
        return 0

    # 6. Instantiate target adapter
    if target_adapter == "http" or (target_url and (target_url.startswith(("http://", "https://")))):
        from evaluator.targets.http_adapter import HttpTargetAdapter

        endpoint = target_url or target_id
        headers = {"X-Raven-Scan-Consent": "true"}
        if config and config.target and config.target.headers:
            headers.update(config.target.headers)

        auth_env = os.environ.get("RAVEN_TARGET_AUTH_HEADER_ENV")
        if auth_env and auth_env in os.environ:
            headers["Authorization"] = f"Bearer {os.environ[auth_env]}"

        req_template = (config.target.request_template if config and config.target else None) or {"message": "{prompt}"}
        resp_path = (config.target.response_json_path if config and config.target else None) or "response"
        timeout_s = (config.target.timeout_seconds if config and config.target else None) or 30.0
        mode = (config.target.mode if config and config.target else None) or "evaluation_only"

        target = HttpTargetAdapter(
            endpoint_url=endpoint,
            headers=headers,
            request_template=req_template,
            response_json_path=resp_path,
            timeout_seconds=timeout_s,
            mode=mode,
        )
    elif target_id == "shophelper-local" or target_adapter == "shophelper-local":
        target = ShopHelperLocalAdapter()
    else:
        from app.domain.entities import Scan, ScanConfig
        from app.domain.value_objects import TargetRef

        from evaluator.targets.factory import build_target

        target_ref = TargetRef(
            target_id=target_id,
            kind="local",
        )
        scan = Scan(
            scan_id="scan_" + os.urandom(4).hex(),
            target=target_ref,
            config=ScanConfig(target_id=target_id),
        )
        target = build_target(scan)

    profile = await target.profile()

    from evaluator.orchestration.phases import _judge_context

    judge_ctx = _judge_context(target, profile)

    # 7. Configure execution budget
    if config and config.budget:
        budget_config = Budget(
            max_attack_cases=len(cases),
            max_attempts_per_attack=config.budget.max_attempts_per_attack,
            max_model_calls=config.budget.max_model_calls,
            max_total_tokens=config.budget.max_total_tokens,
            per_call_timeout_seconds=config.budget.per_call_timeout_seconds,
            scan_timeout_seconds=config.budget.scan_timeout_seconds,
            concurrency_limit=config.budget.concurrency_limit,
        )
    else:
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

    scan_id = "ci_run_" + os.urandom(4).hex()
    test_run, verdicts = await runner.run_security(target, cases, scan_id, RunPhase.BEFORE)

    confirmed_failures = [
        v for v in verdicts if v[2].final_label == FindingLabel.CONFIRMED_FAILURE
    ]
    likely_failures = [
        v for v in verdicts if v[2].final_label == FindingLabel.LIKELY_FAILURE
    ]
    needs_review = [
        v for v in verdicts if v[2].final_label == FindingLabel.NEEDS_REVIEW
    ]
    blocked = [
        v for v in verdicts if v[2].final_label == FindingLabel.ATTACK_BLOCKED
    ]

    high_critical_failures = [
        v for v in verdicts
        if v[2].final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE)
        and v[0].severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    # Evaluate whether failure threshold was crossed
    breached_threshold = should_fail_on_severity(
        verdicts,
        threshold=fail_on_threshold,
        fail_on_breach=fail_on_breach,
    )

    # 8. Output rendering
    if output_format == "json":
        summary = {
            "target": target_id,
            "regression_only": regression_only,
            "total_cases": len(cases),
            "confirmed_failures": len(confirmed_failures),
            "likely_failures": len(likely_failures),
            "high_critical_failures": len(high_critical_failures),
            "needs_review": len(needs_review),
            "blocked": len(blocked),
            "fail_on_threshold": fail_on_threshold,
            "breached_threshold": breached_threshold,
            "attack_success_rate": test_run.metrics.get("attack_success_rate", 0.0),
            "results": test_run.results,
        }
        print(json.dumps(summary, indent=2))
    elif output_format == "sarif":
        sarif_doc = _emit_sarif(cases, verdicts, target_id)
        print(json.dumps(sarif_doc, indent=2))
    elif output_format == "junit":
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuite name="raven-security-gate" tests="{len(cases)}" failures="{len(confirmed_failures)}">',
        ]
        for case, _, verdict, _ in verdicts:
            xml_lines.append(f'  <testcase classname="security.{case.category.value}" name="{case.id}: {case.goal}">')
            if verdict.final_label == FindingLabel.CONFIRMED_FAILURE:
                xml_lines.append(f'    <failure message="Confirmed breach of security rule: {case.success_rule}">')
                xml_lines.append(f'      {verdict.resolution.value}')
                xml_lines.append("    </failure>")
            xml_lines.append("  </testcase>")
        xml_lines.append("</testsuite>")
        print("\n".join(xml_lines))
    else:
        print("=" * 60)
        print("RAVEN Continuous Security Gate — Regression Test Runner")
        mode_label = "Active Regression Tests" if regression_only else "Evaluation Suite"
        print(f"Target: {target_id} | Mode: {mode_label} | Cases: {len(cases)} | Fail-On: >= {fail_on_threshold.upper()}")
        print("=" * 60)
        for case, _, verdict, _ in verdicts:
            status_symbol = "❌ FAIL" if verdict.final_label == FindingLabel.CONFIRMED_FAILURE else "✅ PASS"
            print(f"[{status_symbol}] {case.id} (v{case.version}, {case.category.value}, {case.severity.value}): {case.goal} → {verdict.final_label.value}")

        print("-" * 60)
        print(f"Total: {len(cases)} | Failures: {len(confirmed_failures)} | Blocked: {len(blocked)} | Review: {len(needs_review)}")
        print(f"Attack Success Rate: {test_run.metrics.get('attack_success_rate', 0.0) * 100:.1f}%")
        if not breached_threshold:
            print(f"All evaluated cases satisfied security threshold '{fail_on_threshold}'. Target '{target_id}' is clean.")
        else:
            print(f"FAILED: Security breaches meeting or exceeding '{fail_on_threshold}' threshold detected.")
        print("=" * 60)

    if breached_threshold:
        return 1
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    code = asyncio.run(run_cli(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
