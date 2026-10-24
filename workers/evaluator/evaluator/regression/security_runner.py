"""Security regression runner: executes the attack suite against a target.

Used for both the "before" pass (vulnerable target) and the "after" pass
(hardened target). Each case gets at most max_attempts_per_attack attempts
with at most one mutation per failed case.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.domain.entities import (
    AttackCase,
    TargetRequest,
    TargetResponse,
    TestRun,
    Transcript,
    TranscriptMessage,
)
from app.domain.enums import FindingLabel, RunPhase, TestRunKind

from evaluator.attacks.mutation import mutate_seed
from evaluator.judges.deterministic import DeterministicJudge, JudgeContext
from evaluator.judges.resolver import VerdictResolver
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.targets.base import TargetAdapter


class SecurityRegressionRunner:
    """Runs attack cases and produces per-case results + verdicts."""

    def __init__(
        self,
        judge_context: JudgeContext,
        budget: BudgetTracker,
        resolver: VerdictResolver | None = None,
    ) -> None:
        self._judge = DeterministicJudge(judge_context)
        self._budget = budget
        self._resolver = resolver or VerdictResolver()

    async def run_security(
        self,
        target: TargetAdapter,
        cases: list[AttackCase],
        scan_id: str,
        phase: RunPhase = RunPhase.BEFORE,
    ) -> tuple[TestRun, list]:
        """Returns (TestRun, list[(case, run_id, verdict, transcript)])."""
        results: list[dict[str, Any]] = []
        verdicts: list[tuple[AttackCase, str, Any, Transcript]] = []

        for case in cases:
            outcome = await self._run_case(target, case, scan_id, phase)
            results.append(outcome["result"])
            verdicts.append(
                (case, outcome["run_id"], outcome["verdict"], outcome["transcript"])
            )

        test_run = TestRun(
            test_run_id=f"tr_{uuid.uuid4().hex[:12]}",
            scan_id=scan_id,
            kind=TestRunKind.SECURITY_AFTER if phase == RunPhase.AFTER else TestRunKind.SECURITY_BEFORE,
            metrics={
                "attack_success_rate": _rate(results),
                "blocked_rate": _blocked(results),
                "cases": len(results),
                "phase": phase.value,
            },
            results=results,
            created_at=datetime.now(UTC),
        )
        return test_run, verdicts

    async def _run_case(
        self, target: TargetAdapter, case: AttackCase, scan_id: str, phase: RunPhase
    ) -> dict[str, Any]:
        max_attempts = self._budget.budget.max_attempts_per_attack
        best: dict[str, Any] | None = None

        for attempt in range(1, max_attempts + 1):
            self._budget.consume_attempt(case.id)
            prompt = case.seed_prompt if attempt == 1 else mutate_seed(case.seed_prompt, attempt)
            run_id = f"run_{uuid.uuid4().hex[:12]}"
            try:
                response = await target.invoke(
                    TargetRequest(scan_id=scan_id, run_id=run_id, message=prompt)
                )
            except Exception as exc:  # noqa: BLE001 - target failure: mark not evaluated
                best = {
                    "result": {
                        "attack_id": case.id,
                        "label": FindingLabel.NOT_EVALUATED.value,
                        "attempt": attempt,
                        "error": str(exc),
                    },
                    "run_id": run_id,
                    "verdict": None,
                    "transcript": None,
                }
                break

            transcript = _transcript_from_response(run_id, prompt, response)
            rule_result = await self._judge.evaluate(case, transcript)
            verdict = self._resolver.resolve(scan_id, run_id, rule_result, None, transcript)
            outcome = {
                "result": {
                    "attack_id": case.id,
                    "label": verdict.final_label.value,
                    "attempt": attempt,
                    "signals": rule_result.signals,
                    "resolution": verdict.resolution.value,
                },
                "run_id": run_id,
                "verdict": verdict,
                "transcript": transcript,
            }
            if best is None or _is_better(outcome["result"], best["result"]):
                best = outcome
            if verdict.final_label == FindingLabel.CONFIRMED_FAILURE:
                break  # attack reproduced; no need for another attempt

        assert best is not None
        return best


def _transcript_from_response(
    run_id: str, prompt: str, response: TargetResponse
) -> Transcript:
    messages = [TranscriptMessage(role="user", content=prompt)]
    for call in response.tool_calls:
        messages.append(
            TranscriptMessage(
                role="assistant",
                content=response.message,
                tool_name=str(call.get("tool", "")),
                tool_args_json=str(call.get("arguments", {})),
            )
        )
    if not response.tool_calls:
        messages.append(TranscriptMessage(role="assistant", content=response.message))
    return Transcript(transcript_id=f"t_{run_id}", messages=messages)


def _is_better(candidate: dict[str, Any], current: dict[str, Any]) -> bool:
    """Prefer confirmed_failure > likely_failure > needs_review > blocked."""
    rank = {
        FindingLabel.CONFIRMED_FAILURE.value: 0,
        FindingLabel.LIKELY_FAILURE.value: 1,
        FindingLabel.NEEDS_REVIEW.value: 2,
        FindingLabel.NOT_EVALUATED.value: 3,
        FindingLabel.ATTACK_BLOCKED.value: 4,
    }
    return rank.get(candidate["label"], 9) < rank.get(current["label"], 9)


def _rate(results: list[dict[str, Any]]) -> float:
    from evaluator.regression.metrics import attack_success_rate

    return attack_success_rate(results)


def _blocked(results: list[dict[str, Any]]) -> float:
    from evaluator.regression.metrics import blocked_rate

    return blocked_rate(results)
