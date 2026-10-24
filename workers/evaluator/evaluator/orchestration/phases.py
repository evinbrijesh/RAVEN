"""Scan engine: drives the bounded state machine for one scan.

Phases (blueprint §6): recon → attack → judge → harden → approval gate →
retest → complete. Every transition is persisted and emitted. The engine
never calls a model in the control plane and never applies hardening without
a recorded approval.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from app.domain.entities import (
    Finding,
    HardeningProposal,
    ScanEvent,
    TestRun,
)
from app.domain.enums import (
    EventKind,
    FindingLabel,
    RunPhase,
    ScanStatus,
    Severity,
    TestRunKind,
)
from app.domain.errors import RavenError
from app.infrastructure.db.repository import Repositories

from evaluator.attacks.planner import AttackPlanner
from evaluator.config import get_worker_settings
from evaluator.hardening.policy_compiler import PolicyCompiler
from evaluator.hardening.prompt_hardener import PromptHardener
from evaluator.hardening.proposal_validator import ProposalValidator
from evaluator.judges.deterministic import JudgeContext
from evaluator.judges.resolver import VerdictResolver
from evaluator.judges.semantic import SemanticJudge, get_model_client
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.orchestration.state_machine import transition
from evaluator.regression.security_runner import SecurityRegressionRunner
from evaluator.regression.utility_runner import UtilityRegressionRunner
from evaluator.targets.factory import build_target

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class ScanEngine:
    """Executes one scan end-to-end (minus the approval wait)."""

    def __init__(self, repos: Repositories, fixtures_path: str | None = None) -> None:
        self._repos = repos
        self._fixtures_path = fixtures_path
        self._planner = AttackPlanner()
        settings = get_worker_settings()
        self._model_client = get_model_client(
            provider=settings.model_provider,
            api_key=settings.model_api_key,
            model_name=settings.model_name,
            base_url=settings.model_base_url,
        )
        self._model_name = settings.model_name

    def _create_target(self, scan):
        return build_target(scan, self._fixtures_path)

    async def run(self, scan_id: str) -> None:
        scan = self._repos.scans.get(scan_id)
        if scan is None:
            raise RavenError(f"Scan '{scan_id}' not found.")
        budget = BudgetTracker(budget=scan.config.budget)
        target = self._create_target(scan)

        try:
            profile = await self._phase_recon(scan_id, target, budget)
            findings = await self._phase_attack_and_judge(scan_id, target, budget, profile)
            await self._phase_hardening(scan_id, findings)
            # Scan now rests in AWAITING_APPROVAL; the approval endpoint moves
            # it to RETESTING, and run_retest finishes the scan.
        except RavenError:
            await self._fail(scan_id, ScanStatus.FAILED_FATAL)
            raise
        except Exception as exc:  # unexpected: fail loudly, keep evidence
            self._emit(scan_id, EventKind.ERROR, {"error": str(exc)})
            await self._fail(scan_id, ScanStatus.FAILED_FATAL)
            raise

    async def run_retest(self, scan_id: str) -> None:
        """After approval: apply hardening to the temporary target and retest."""
        scan = self._repos.scans.get(scan_id)
        if scan is None:
            raise RavenError(f"Scan '{scan_id}' not found.")
        proposal = self._repos.proposals.latest_for_scan(scan_id)
        if proposal is None:
            await self._fail(scan_id, ScanStatus.FAILED_PARTIAL)
            raise RavenError("No proposal to retest.")

        budget = BudgetTracker(budget=scan.config.budget)
        target = self._create_target(scan)
        if getattr(target, "mode", None) == "evaluation_only":
            self._set_status(scan_id, ScanStatus.COMPLETED_WITHOUT_RETEST, 1.0)
            self._emit(
                scan_id,
                EventKind.SCAN_COMPLETED,
                {
                    "status": "completed_without_retest",
                    "reason": "External target is evaluation_only; remote hardening cannot be applied without an authorized staging contract.",
                },
            )
            return

        try:
            self._set_status(scan_id, ScanStatus.RETESTING, 0.8)
            self._emit(scan_id, EventKind.RETEST_STARTED, {"proposal_id": proposal.proposal_id})
            await target.apply_temporary_policy(
                proposal.policy_candidate, proposal.prompt_diff and _hardened_prompt(proposal)
            )
            profile = await target.profile()
            judge_ctx = _judge_context(target, profile)
            semantic_judge = (
                SemanticJudge(self._model_client, budget, self._model_name)
                if self._model_client is not None and budget.budget.max_model_calls > 0
                else None
            )
            runner = SecurityRegressionRunner(judge_ctx, budget, semantic_judge=semantic_judge)
            cases = self._select_cases(scan)
            after_run, after_verdicts = await runner.run_security(target, cases, scan_id, RunPhase.AFTER)
            self._persist_test_run(after_run)
            for case, run_id, verdict, transcript in after_verdicts:
                self._repos.db.execute(
                    "INSERT OR REPLACE INTO attack_runs (run_id, scan_id, attack_case_id, attempt, phase, started_at, finished_at, status, transcript_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        scan_id,
                        case.id,
                        1,
                        RunPhase.AFTER.value,
                        verdict.created_at.isoformat(),
                        verdict.created_at.isoformat(),
                        "completed",
                        transcript.model_dump_json() if transcript else None,
                    ),
                )
                if transcript is not None:
                    self._repos.runs.save_transcript(transcript, run_id)
                self._repos.runs.save_verdict(verdict)

            utility_runner = UtilityRegressionRunner()
            benign_cases = self._planner.load_benign_cases()
            utility_run = await utility_runner.run_utility(target, benign_cases, scan_id)
            self._persist_test_run(utility_run)

            await self._save_regressions(scan_id, scan.target.target_id, after_run)

            self._set_status(scan_id, ScanStatus.COMPLETED, 1.0)
            self._emit(scan_id, EventKind.SCAN_COMPLETED, {"status": "completed"})
        except RavenError:
            await self._fail(scan_id, ScanStatus.FAILED_PARTIAL)
            raise
        except Exception as exc:
            self._emit(scan_id, EventKind.ERROR, {"error": str(exc)})
            await self._fail(scan_id, ScanStatus.FAILED_PARTIAL)
            raise

    # --- phases -----------------------------------------------------------
    async def _phase_recon(self, scan_id: str, target, budget: BudgetTracker):
        self._set_status(scan_id, ScanStatus.RECONNING, 0.05)
        from evaluator.attacks.recon import ReconAgent
        recon_agent = ReconAgent(target)
        profile = await recon_agent.execute_recon(scan_id)
        self._repos.profiles.save(scan_id, profile)
        self._emit(
            scan_id,
            EventKind.RECON_COMPLETED,
            {
                "tools": profile.tools,
                "canary_present": bool(profile.canary_token),
                "refusal_behavior": profile.refusal_behavior,
            },
        )
        return profile

    async def _phase_attack_and_judge(self, scan_id, target, budget, profile) -> list[Finding]:
        self._set_status(scan_id, ScanStatus.ATTACKING, 0.15)
        scan = self._repos.scans.get(scan_id)
        assert scan is not None
        if scan.config.regression_only_mode:
            # Regression-only: filter the FULL catalog by active regression
            # ids first, then cap by budget (B6: never slice before filtering,
            # never fall back to arbitrary attacks). Empty selection runs zero
            # cases and the report marks the scan inconclusive.
            cases = self._select_regression_cases(scan)
        else:
            cases = self._planner.select(
                [c.value for c in scan.config.attack_categories],
                scan.config.budget.max_attack_cases,
            )
        judge_ctx = _judge_context(target, profile)
        semantic_judge = (
            SemanticJudge(self._model_client, budget, self._model_name)
            if self._model_client is not None and budget.budget.max_model_calls > 0
            else None
        )
        runner = SecurityRegressionRunner(
            judge_ctx, budget, VerdictResolver(), semantic_judge=semantic_judge
        )

        self._set_status(scan_id, ScanStatus.JUDGING, 0.4)
        before_run, verdicts = await runner.run_security(target, cases, scan_id, RunPhase.BEFORE)
        self._persist_test_run(before_run)

        # Pre-hardening benign baseline: required for the over-refusal delta
        # (ADR 0001 data prerequisites). Runs against the vulnerable target.
        if scan.config.run_benign_suite:
            utility_runner = UtilityRegressionRunner()
            baseline = await utility_runner.run_utility(
                target, self._planner.load_benign_cases(), scan_id
            )
            baseline.kind = TestRunKind.UTILITY_BEFORE
            baseline.metrics = {**baseline.metrics, "phase": "before"}
            self._persist_test_run(baseline)

        findings: list[Finding] = []
        for case, run_id, verdict, transcript in verdicts:
            self._repos.db.execute(
                "INSERT OR REPLACE INTO attack_runs (run_id, scan_id, attack_case_id, attempt, phase, started_at, finished_at, status, transcript_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    scan_id,
                    case.id,
                    1,
                    RunPhase.BEFORE.value,
                    verdict.created_at.isoformat(),
                    verdict.created_at.isoformat(),
                    "completed",
                    transcript.model_dump_json() if transcript else None,
                ),
            )
            if transcript is not None:
                self._repos.runs.save_transcript(transcript, run_id)
            self._repos.runs.save_verdict(verdict)
            self._emit(
                scan_id,
                EventKind.VERDICT_CREATED,
                {"attack_id": case.id, "label": verdict.final_label.value},
            )
            if verdict.final_label in (
                FindingLabel.CONFIRMED_FAILURE,
                FindingLabel.LIKELY_FAILURE,
                FindingLabel.NEEDS_REVIEW,
            ):
                from evaluator.judges.weakness import derive_weak_point

                sys_prompt = ""
                if hasattr(target, "fixtures_path"):
                    sys_prompt = (target.fixtures_path / "system-prompt.txt").read_text(encoding="utf-8")

                weak_pt = derive_weak_point(
                    case=case,
                    verdict=verdict,
                    transcript=transcript,
                    system_prompt=sys_prompt,
                )
                import hashlib

                finding_key = hashlib.sha256(f"{scan_id}:{case.id}".encode()).hexdigest()[:12]
                finding = Finding(
                    finding_id=f"find_{finding_key}",
                    scan_id=scan_id,
                    attack_id=case.id,
                    category=case.category,
                    severity=case.severity,
                    label=verdict.final_label,
                    confidence=verdict.llm_result.confidence if verdict.llm_result else (1.0 if verdict.final_label == FindingLabel.CONFIRMED_FAILURE else 0.5),
                    summary=f"{case.goal} — {verdict.resolution.value}",
                    evidence_refs=verdict.evidence_refs,
                    needs_review=verdict.final_label == FindingLabel.NEEDS_REVIEW,
                    weak_point=weak_pt,
                )
                self._repos.findings.save(finding)
                findings.append(finding)
        return findings

    async def _phase_hardening(self, scan_id: str, findings: list[Finding]) -> None:
        if not findings:
            self._set_status(scan_id, ScanStatus.COMPLETED, 1.0)
            self._emit(scan_id, EventKind.SCAN_COMPLETED, {"status": "completed_no_findings"})
            return

        self._set_status(scan_id, ScanStatus.HARDENING_PROPOSED, 0.7)
        scan = self._repos.scans.get(scan_id)
        assert scan is not None
        target = self._create_target(scan)
        await target.profile()
        original_prompt = ""
        if hasattr(target, "fixtures_path"):
            original_prompt = (target.fixtures_path / "system-prompt.txt").read_text(encoding="utf-8")
        else:
            original_prompt = "You are a customer assistant endpoint."

        hardener = PromptHardener()
        _hardened_prompt, diff = hardener.propose(original_prompt)
        compiler = PolicyCompiler()
        candidate = compiler.compile(findings)
        orig_policy = {}
        if hasattr(target, "fixtures_path"):
            orig_policy = json.loads((target.fixtures_path / "vulnerable-policy.json").read_text(encoding="utf-8"))
        p_diff = compiler.diff(orig_policy, candidate)

        existing_proposal = self._repos.proposals.latest_for_scan(scan_id)
        if existing_proposal is not None:
            proposal = existing_proposal
        else:
            proposal = HardeningProposal(
                proposal_id=f"fix_{uuid.uuid4().hex[:12]}",
                scan_id=scan_id,
                prompt_diff=diff,
                policy_diff=p_diff,
                policy_candidate=candidate,
            rationale=(
                "Multi-layer defense-in-depth: prompt refusal hardening paired with "
                "strict deterministic policy gateway constraints on tool execution."
            ),
            affected_cases=[f.attack_id for f in findings],
            risks=[
                "Hardened prompt may reduce assistant helpfulness on edge cases.",
                "Refund conditions may block legitimate refunds without verification.",
            ],
        )
        validator = ProposalValidator()
        validator.validate_or_raise(proposal)
        self._repos.proposals.save(proposal)
        self._emit(
            scan_id,
            EventKind.HARDENING_PROPOSED,
            {"proposal_id": proposal.proposal_id, "has_policy": candidate is not None},
        )
        self._set_status(scan_id, ScanStatus.AWAITING_APPROVAL, 0.75)

    # --- helpers ------------------------------------------------------------
    def _select_cases(self, scan) -> list:
        """Case selection for a security pass, honoring regression-only mode."""
        if not scan.config.regression_only_mode:
            return self._planner.select(
                [c.value for c in scan.config.attack_categories],
                scan.config.budget.max_attack_cases,
            )
        return self._select_regression_cases(scan)

    def _select_regression_cases(self, scan) -> list:
        """Regression-only selection: full catalog → filter by active
        regression ids → cap by budget. Fail closed: unknown persisted ids are
        skipped, and an empty selection runs zero cases (never arbitrary
        attacks)."""
        from evaluator.attacks.planner import load_attack_cases

        active = self._repos.regressions.list_active(scan.target.target_id)
        reg_ids = {r["attack_case_id"] for r in active}
        categories = (
            [c.value for c in scan.config.attack_categories] or None
        )
        catalog = load_attack_cases(categories, limit=None)
        selected = [c for c in catalog if c.id in reg_ids]
        return selected[: scan.config.budget.max_attack_cases]

    def _persist_test_run(self, run: TestRun) -> None:
        self._repos.test_runs.save(run)

    async def _save_regressions(self, scan_id: str, target_id: str, after_run: TestRun) -> None:
        """Persist blocked attack cases as versioned regression cases.

        Cases come from the versioned catalog (never stubs) and promotion is
        deduplicated per target: one active regression per attack id.
        """
        from app.application.catalog import load_catalog_cases

        already_active = {
            row["attack_case_id"]
            for row in self._repos.regressions.list_active(target_id)
        }
        catalog = {case.id: case for case in load_catalog_cases()}
        saved = 0
        for result in after_run.results:
            if result.get("label") != FindingLabel.ATTACK_BLOCKED.value:
                continue
            case_id = str(result.get("attack_id", ""))
            case = catalog.get(case_id)
            if case is None or case_id in already_active:
                continue
            self._repos.regressions.save_case(
                target_id,
                case,
                case.model_dump_json(),
            )
            already_active.add(case_id)
            saved += 1
        self._emit(scan_id, EventKind.REGRESSION_SAVED, {"count": saved})

    def _set_status(self, scan_id: str, status: ScanStatus, progress: float) -> None:
        scan = self._repos.scans.get(scan_id)
        if scan is None:
            return
        transition(scan, status)
        self._repos.scans.update_status(scan_id, scan.status, progress)
        self._emit(scan_id, EventKind.PHASE_CHANGED, {"status": scan.status.value, "progress": progress})

    def _emit(self, scan_id: str, kind: EventKind, payload: dict[str, Any]) -> None:
        self._repos.events.append(ScanEvent(scan_id=scan_id, kind=kind, payload=payload))

    async def _fail(self, scan_id: str, status: ScanStatus) -> None:
        scan = self._repos.scans.get(scan_id)
        if scan is None or _terminal(scan.status):
            return
        self._repos.scans.update_status(scan_id, status)
        self._emit(scan_id, EventKind.SCAN_FAILED, {"status": status.value})


def _terminal(status: ScanStatus) -> bool:
    from evaluator.orchestration.state_machine import is_terminal

    return is_terminal(status)


def _hardened_prompt(proposal: HardeningProposal) -> str:
    from evaluator.hardening.prompt_hardener import harden_prompt

    return harden_prompt("")


def _judge_context(target, profile):
    import json

    from evaluator.targets.shophelper import fixtures_dir

    customers = json.loads((fixtures_dir() / "fake-customers.json").read_text(encoding="utf-8"))
    return JudgeContext(
        canary_token=profile.canary_token,
        system_prompt=(fixtures_dir() / "system-prompt.txt").read_text(encoding="utf-8"),
        customer_emails=[c["email"] for c in customers],
        customer_phones=[c["phone"] for c in customers],
    )
