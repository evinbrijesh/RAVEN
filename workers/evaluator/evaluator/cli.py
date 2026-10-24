"""RAVEN Standalone CI/CD Regression Runner CLI (`raven-test`).

Executes saved security regression test suites or curated attack catalogs
directly against a target adapter without requiring the full Web UI or API server.
Exits 0 if all tests pass (or no security regressions are detected),
or 1 if an attack successfully breaches or causes a confirmed failure.
"""

from __future__ import annotations

import argparse
import asyncio
import json
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
from evaluator.judges.resolver import VerdictResolver
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.regression.security_runner import SecurityRegressionRunner
from evaluator.targets.shophelper import ShopHelperLocalAdapter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raven-test",
        description="RAVEN Autonomous CI/CD Security Regression Gate",
    )
    parser.add_argument(
        "--target",
        default="shophelper-local",
        help="Target adapter to execute against (default: shophelper-local)",
    )
    parser.add_argument(
        "--regression-only",
        action="store_true",
        default=False,
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
        default="text",
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
        default=10,
        help="Maximum attack cases to run (default: 10)",
    )
    parser.add_argument(
        "--fail-on-breach",
        action="store_true",
        default=True,
        help="Exit with non-zero exit code if any confirmed breach occurs (default: True)",
    )
    return parser


def load_suite(
    path: str | None, categories: list[str] | None, limit: int, regression_only: bool, target_id: str
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
    cases, no_regression_cases = load_suite(
        args.suite, args.categories, args.max_cases, args.regression_only, args.target
    )

    if no_regression_cases:
        if args.output == "json":
            print(json.dumps({
                "target": args.target,
                "status": "no_regression_cases",
                "message": f"No active regression cases registered for target '{args.target}'.",
                "total_cases": 0,
            }, indent=2))
        elif args.output == "sarif":
            print(json.dumps(_emit_sarif([], [], args.target), indent=2))
        else:
            print(f"[RAVEN CI] No active regression cases registered for target '{args.target}'.", file=sys.stderr)
        return 0

    if not cases:
        print("[RAVEN CI] No attack test cases found to execute.", file=sys.stderr)
        return 0

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

    # Critical or high reopened failures
    high_critical_failures = [
        v for v in verdicts
        if v[2].final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE)
        and v[0].severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    if args.output == "json":
        summary = {
            "target": args.target,
            "regression_only": args.regression_only,
            "total_cases": len(cases),
            "confirmed_failures": len(confirmed_failures),
            "likely_failures": len(likely_failures),
            "high_critical_failures": len(high_critical_failures),
            "needs_review": len(needs_review),
            "blocked": len(blocked),
            "attack_success_rate": test_run.metrics.get("attack_success_rate", 0.0),
            "results": test_run.results,
        }
        print(json.dumps(summary, indent=2))
    elif args.output == "sarif":
        sarif_doc = _emit_sarif(cases, verdicts, args.target)
        print(json.dumps(sarif_doc, indent=2))
    elif args.output == "junit":
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
        mode_label = "Active Regression Tests" if args.regression_only else "Evaluation Suite"
        print(f"Target: {args.target} | Mode: {mode_label} | Cases: {len(cases)}")
        print("=" * 60)
        for case, _, verdict, _ in verdicts:
            status_symbol = "❌ FAIL" if verdict.final_label == FindingLabel.CONFIRMED_FAILURE else "✅ PASS"
            print(f"[{status_symbol}] {case.id} (v{case.version}, {case.category.value}): {case.goal} → {verdict.final_label.value}")

        print("-" * 60)
        print(f"Total: {len(cases)} | Failures: {len(confirmed_failures)} | Blocked: {len(blocked)} | Review: {len(needs_review)}")
        print(f"Attack Success Rate: {test_run.metrics.get('attack_success_rate', 0.0) * 100:.1f}%")
        if len(confirmed_failures) == 0:
            print(f"All {len(cases)} regression cases passed. Target '{args.target}' is clean.")
        print("=" * 60)

    if args.fail_on_breach and (len(high_critical_failures) > 0 or len(confirmed_failures) > 0):
        return 1
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    code = asyncio.run(run_cli(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
