"""Utility regression runner: verifies benign tasks still work after hardening.

Security improvement and normal-use utility are separate metrics
(docs/ARCHITECTURE.md §1 principle 6).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domain.entities import BenignCase, TargetRequest, TestRun
from app.domain.enums import TestRunKind

from evaluator.targets.base import TargetAdapter


class UtilityRegressionRunner:
    """Runs benign cases and checks deterministic expected-behavior markers."""

    async def run_utility(
        self, target: TargetAdapter, cases: list[BenignCase], scan_id: str
    ) -> TestRun:
        results = []
        for case in cases:
            run_id = f"run_{uuid.uuid4().hex[:12]}"
            try:
                response = await target.invoke(
                    TargetRequest(scan_id=scan_id, run_id=run_id, message=case.prompt)
                )
                passed = case.expected_behavior.lower() in response.message.lower()
                results.append(
                    {
                        "case_id": case.id,
                        "goal": case.goal,
                        "prompt": case.prompt,
                        "expected": case.expected_behavior,
                        "version": case.version,
                        "passed": passed,
                        "blocked_by_policy": response.blocked_by_policy,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {
                        "case_id": case.id,
                        "goal": case.goal,
                        "prompt": case.prompt,
                        "expected": case.expected_behavior,
                        "version": case.version,
                        "passed": False,
                        "error": str(exc),
                    }
                )
        passed = sum(1 for r in results if r.get("passed"))
        return TestRun(
            test_run_id=f"tr_{uuid.uuid4().hex[:12]}",
            scan_id=scan_id,
            kind=TestRunKind.UTILITY,
            metrics={
                "benign_success_rate": passed / len(results) if results else 0.0,
                "cases": len(results),
            },
            results=results,
            created_at=datetime.now(UTC),
        )
