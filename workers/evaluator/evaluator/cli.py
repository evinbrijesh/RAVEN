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
from app.domain.enums import FindingLabel, RunPhase

from evaluator.attacks.planner import load_attack_cases
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
        "--suite",
        default=None,
        help="Path to custom regression suite JSON file (default: loads from attack catalog)",
    )
    parser.add_argument(
        "--output",
        choices=["json", "junit", "text"],
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


def load_suite(path: str | None, categories: list[str] | None, limit: int) -> list[AttackCase]:
    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Suite file not found: {path}")
        raw = json.loads(p.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("attack_cases", raw.get("cases", []))
        cases = [AttackCase.model_validate(c) for c in items]
        if categories:
            cases = [c for c in cases if c.category.value in categories]
        return cases[:limit]
    return load_attack_cases(categories, limit=limit)


async def run_cli(args: argparse.Namespace) -> int:
    cases = load_suite(args.suite, args.categories, args.max_cases)
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

    if args.output == "json":
        summary = {
            "target": args.target,
            "total_cases": len(cases),
            "confirmed_failures": len(confirmed_failures),
            "likely_failures": len(likely_failures),
            "needs_review": len(needs_review),
            "blocked": len(blocked),
            "attack_success_rate": test_run.metrics.get("attack_success_rate", 0.0),
            "results": test_run.results,
        }
        print(json.dumps(summary, indent=2))
    elif args.output == "junit":
        # Generate minimal JUnit XML for CI test reports
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
        print(f"Target: {args.target} | Cases: {len(cases)}")
        print("=" * 60)
        for case, _, verdict, _ in verdicts:
            status_symbol = "❌ FAIL" if verdict.final_label == FindingLabel.CONFIRMED_FAILURE else "✅ PASS"
            print(f"[{status_symbol}] {case.id} ({case.category.value}): {case.goal} → {verdict.final_label.value}")

        print("-" * 60)
        print(f"Total: {len(cases)} | Failures: {len(confirmed_failures)} | Blocked: {len(blocked)} | Review: {len(needs_review)}")
        print(f"Attack Success Rate: {test_run.metrics.get('attack_success_rate', 0.0) * 100:.1f}%")
        print("=" * 60)

    if args.fail_on_breach and len(confirmed_failures) > 0:
        return 1
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    code = asyncio.run(run_cli(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
