"""Typed LangGraph Workflow for RAVEN Scan Orchestration.

Formalizes the 13-node closed-loop architecture:
START
  -> initialize_scan
  -> recon
  -> plan_attacks
  -> execute_security_tests
  -> judge_results
  -> resolve_verdicts
  -> generate_hardening_proposal
  -> human_approval_interrupt
  -> retest_security
  -> retest_benign_utility
  -> calculate_metrics
  -> promote_regressions
  -> generate_reports
  -> END

Supports terminal paths:
- completed
- completed_without_retest
- failed_partial
- failed_fatal
- inconclusive
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import TYPE_CHECKING, Any

from app.application.catalog import load_catalog_case
from app.application.report.service import generate as generate_report
from app.domain.entities import (
    Approval,
    Finding,
    HardeningProposal,
    LlmJudgeResult,
    RuleResult,
    TestRun,
    utc_now,
)
from app.domain.enums import (
    EventKind,
    FindingLabel,
    RunPhase,
    ScanStatus,
    TestRunKind,
)
from app.domain.errors import RavenError
from app.security.limits import validate_scan_config
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from evaluator.attacks.recon import ReconAgent
from evaluator.hardening.policy_compiler import PolicyCompiler
from evaluator.hardening.prompt_hardener import PromptHardener
from evaluator.hardening.proposal_validator import ProposalValidator
from evaluator.judges.deterministic import DeterministicJudge, JudgeContext
from evaluator.judges.resolver import VerdictResolver
from evaluator.judges.semantic import SemanticJudge
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.orchestration.state import (
    RavenScanState,
    compute_target_config_hash,
    sanitize_profile_for_state,
)
from evaluator.regression.security_runner import (
    SecurityRegressionRunner,
    _blocked,
    _case_metadata,
    _rate,
)
from evaluator.regression.utility_runner import UtilityRegressionRunner
from evaluator.targets.shophelper import fixtures_dir

if TYPE_CHECKING:
    from langgraph.checkpoint.base import BaseCheckpointSaver

    from evaluator.orchestration.phases import ScanEngine

logger = logging.getLogger("raven.langgraph")


def _hardened_prompt(proposal: HardeningProposal) -> str:
    from evaluator.hardening.prompt_hardener import harden_prompt

    return harden_prompt("")


def _get_judge_context(target, profile):
    try:
        fdir = target.fixtures_path if hasattr(target, "fixtures_path") and target.fixtures_path else fixtures_dir()
        cust_file = fdir / "fake-customers.json"
        customers = json.loads(cust_file.read_text(encoding="utf-8")) if cust_file.exists() else []
        sys_prompt_file = fdir / "system-prompt.txt"
        sys_prompt = sys_prompt_file.read_text(encoding="utf-8") if sys_prompt_file.exists() else "You are ShopHelper."
    except (OSError, json.JSONDecodeError):
        customers = []
        sys_prompt = "You are ShopHelper."

    return JudgeContext(
        canary_token=profile.canary_token if profile else "",
        system_prompt=sys_prompt,
        customer_emails=[c.get("email", "") for c in customers if "email" in c],
        customer_phones=[c.get("phone", "") for c in customers if "phone" in c],
    )


def create_raven_graph(engine: ScanEngine, checkpointer: BaseCheckpointSaver | None = None) -> Any:
    """Build and compile the typed LangGraph StateGraph workflow for RAVEN."""
    workflow = StateGraph(RavenScanState)

    # ──────────────────────────────────────────────────────────────────────────
    # 1. initialize_scan
    # ──────────────────────────────────────────────────────────────────────────
    async def initialize_scan_node(state: RavenScanState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        logger.info("[initialize_scan] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            err = f"Scan '{scan_id}' not found."
            logger.error(err)
            await engine._fail(scan_id, ScanStatus.FAILED_FATAL)
            return {
                "status": "failed_fatal",
                "phase": "initialize_failed",
                "errors": state.get("errors", []) + [err],
            }

        try:
            validate_scan_config(scan.config)
        except (ValueError, TypeError, RavenError) as exc:
            err = f"Scan configuration invalid: {exc}"
            logger.error(err)
            await engine._fail(scan_id, ScanStatus.FAILED_FATAL)
            return {
                "status": "failed_fatal",
                "phase": "initialize_failed",
                "errors": state.get("errors", []) + [err],
            }

        target_id = scan.target.target_id
        config_dict = scan.config.model_dump()
        config_hash = compute_target_config_hash(target_id, config_dict)

        engine._emit(
            scan_id,
            EventKind.PHASE_CHANGED,
            {
                "status": scan.status.value,
                "progress": scan.progress,
                "graph_node": "initialize_scan",
                "phase": "initialized",
            },
        )

        return {
            "run_id": f"run_{scan_id}",
            "target_id": target_id,
            "target_configuration_hash": config_hash,
            "scan_configuration": config_dict,
            "phase": "initialized",
            "status": scan.status.value,
            "budget_used": {
                "attempts": 0,
                "model_calls": 0,
                "tokens": 0,
                "duration_seconds": 0.0,
            },
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 2. recon
    # ──────────────────────────────────────────────────────────────────────────
    async def recon_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") == "failed_fatal":
            return state

        scan_id = state["scan_id"]
        logger.info("[recon] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "recon_failed"}

        # Idempotency check: reuse persisted profile if already done
        scan = engine._repos.scans.get(scan_id)
        if scan and scan.status == ScanStatus.CREATED:
            engine._set_status(scan_id, ScanStatus.RECONNING, 0.05)
        profile = engine._repos.profiles.get(scan_id)
        if not profile:
            target = engine._create_target(scan)
            recon_agent = ReconAgent(target)
            try:
                profile = await recon_agent.execute_recon(scan_id)
                engine._repos.profiles.save(scan_id, profile)
                engine._emit(
                    scan_id,
                    EventKind.RECON_COMPLETED,
                    {
                        "tools": profile.tools,
                        "canary_present": bool(profile.canary_token),
                        "refusal_behavior": profile.refusal_behavior,
                        "graph_node": "recon",
                    },
                )
            except Exception as exc:
                logger.exception("Recon failed fatally for scan %s", scan_id)
                await engine._fail(scan_id, ScanStatus.FAILED_FATAL)
                return {
                    "status": "failed_fatal",
                    "phase": "recon_failed",
                    "errors": state.get("errors", []) + [f"Recon failed: {exc}"],
                }

        sanitized_profile = sanitize_profile_for_state(profile.model_dump())
        return {
            "target_profile": sanitized_profile,
            "phase": "recon_completed",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 3. plan_attacks
    # ──────────────────────────────────────────────────────────────────────────
    async def plan_attacks_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("failed_fatal", "failed_partial"):
            return state

        scan_id = state["scan_id"]
        logger.info("[plan_attacks] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "plan_failed"}

        if scan.config.regression_only_mode:
            cases = engine._select_regression_cases(scan)
            if not cases:
                logger.info("Regression-only scan %s has 0 active regression cases -> inconclusive", scan_id)
                return {
                    "selected_attack_case_ids": [],
                    "warnings": state.get("warnings", []) + ["No active regression cases found for target in regression-only mode"],
                    "status": "inconclusive",
                    "phase": "plan_attacks_inconclusive",
                }
        else:
            cases = engine._planner.select(
                [c.value for c in scan.config.attack_categories],
                scan.config.budget.max_attack_cases,
            )

        selected_ids = [c.id for c in cases]
        return {
            "selected_attack_case_ids": selected_ids,
            "phase": "attack_planning_completed",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 4. execute_security_tests
    # ──────────────────────────────────────────────────────────────────────────
    async def execute_security_tests_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("failed_fatal", "failed_partial", "inconclusive"):
            return state

        scan_id = state["scan_id"]
        logger.info("[execute_security_tests] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "execute_failed"}

        engine._set_status(scan_id, ScanStatus.ATTACKING, 0.15)
        target = engine._create_target(scan)
        budget = BudgetTracker(budget=scan.config.budget)
        profile = engine._repos.profiles.get(scan_id)
        judge_ctx = _get_judge_context(target, profile)

        # Pre-hardening benign baseline: required for over-refusal delta
        if scan.config.run_benign_suite:
            existing_baselines = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.UTILITY_BEFORE)
            if not existing_baselines:
                utility_runner = UtilityRegressionRunner()
                baseline = await utility_runner.run_utility(
                    target, engine._planner.load_benign_cases(), scan_id
                )
                baseline.kind = TestRunKind.UTILITY_BEFORE
                baseline.metrics = {**baseline.metrics, "phase": "before"}
                engine._persist_test_run(baseline)

        # Per-case idempotency check: reuse any attack runs already completed for this scan in BEFORE phase
        existing_runs = engine._repos.runs.list_runs(scan_id)
        before_runs_by_case = {
            r["attack_case_id"]: r for r in existing_runs if r.get("phase") == RunPhase.BEFORE.value
        }

        cases = engine._select_cases(scan)
        selected_set = set(state.get("selected_attack_case_ids", []))
        cases_to_run = [c for c in cases if c.id in selected_set]

        semantic_judge = (
            SemanticJudge(engine._model_client, budget, engine._model_name)
            if engine._model_client is not None and budget.budget.max_model_calls > 0
            else None
        )
        runner = SecurityRegressionRunner(
            judge_ctx, budget, VerdictResolver(), semantic_judge=semantic_judge
        )

        attack_results = []
        for case in cases_to_run:
            # Check for mid-run cancellation
            curr_scan = engine._repos.scans.get(scan_id)
            if curr_scan and curr_scan.status in (ScanStatus.FAILED_PARTIAL, ScanStatus.FAILED_FATAL):
                logger.warning("Scan %s cancelled during attack execution", scan_id)
                return {
                    "attack_results": attack_results,
                    "status": "failed_partial",
                    "phase": "cancelled",
                }

            if case.id in before_runs_by_case:
                r = before_runs_by_case[case.id]
                attack_results.append({
                    "run_id": r["run_id"],
                    "attack_id": r["attack_case_id"],
                    "attempt": r["attempt"],
                    "status": r["status"],
                })
                continue

            engine._emit(scan_id, EventKind.ATTACK_STARTED, {"attack_id": case.id, "graph_node": "execute_security_tests"})
            outcome = await runner._run_case(target, case, scan_id, RunPhase.BEFORE)
            engine._emit(scan_id, EventKind.ATTACK_FINISHED, {"attack_id": case.id, "graph_node": "execute_security_tests"})

            run_id = outcome["run_id"]
            transcript = outcome["transcript"]
            verdict = outcome["verdict"]

            engine._repos.db.execute(
                "INSERT OR REPLACE INTO attack_runs (run_id, scan_id, attack_case_id, attempt, phase, started_at, finished_at, status, transcript_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    scan_id,
                    case.id,
                    outcome["result"].get("attempt", 1),
                    RunPhase.BEFORE.value,
                    (verdict.created_at if verdict else utc_now()).isoformat(),
                    (verdict.created_at if verdict else utc_now()).isoformat(),
                    "completed",
                    transcript.model_dump_json() if transcript else None,
                ),
            )
            if transcript is not None:
                engine._repos.runs.save_transcript(transcript, run_id)

            attack_results.append({
                "run_id": run_id,
                "attack_id": case.id,
                "attempt": outcome["result"].get("attempt", 1),
                "status": "completed",
            })

        return {
            "attack_results": attack_results,
            "phase": "security_tests_executed",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 5. judge_results
    # ──────────────────────────────────────────────────────────────────────────
    async def judge_results_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("failed_fatal", "failed_partial", "inconclusive"):
            return state

        scan_id = state["scan_id"]
        logger.info("[judge_results] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "judge_failed"}

        engine._set_status(scan_id, ScanStatus.JUDGING, 0.40)
        target = engine._create_target(scan)
        profile = engine._repos.profiles.get(scan_id)
        judge_ctx = _get_judge_context(target, profile)
        budget = BudgetTracker(budget=scan.config.budget)
        det_judge = DeterministicJudge(judge_ctx)

        semantic_judge = (
            SemanticJudge(engine._model_client, budget, engine._model_name)
            if engine._model_client is not None and budget.budget.max_model_calls > 0
            else None
        )

        deterministic_evidence = []
        semantic_judgments = []

        for item in state.get("attack_results", []):
            run_id = item["run_id"]
            case_id = item["attack_id"]
            case = load_catalog_case(case_id)
            transcript = engine._repos.runs.get_transcript(run_id)

            if case and transcript:
                rule_result = await det_judge.evaluate(case, transcript)
                deterministic_evidence.append({
                    "run_id": run_id,
                    "attack_id": case_id,
                    "label": rule_result.label.value,
                    "signals": rule_result.signals,
                })

                if semantic_judge is not None:
                    try:
                        llm_result = await semantic_judge.evaluate(case, transcript)
                        if llm_result:
                            semantic_judgments.append({
                                "run_id": run_id,
                                "attack_id": case_id,
                                "label": llm_result.label.value,
                                "confidence": llm_result.confidence,
                                "reason": llm_result.reason,
                                "model_name": engine._model_name,
                            })
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Semantic judge failed for run %s: %s", run_id, exc)

        return {
            "deterministic_evidence": deterministic_evidence,
            "semantic_judgments": semantic_judgments,
            "phase": "judging_completed",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 6. resolve_verdicts
    # ──────────────────────────────────────────────────────────────────────────
    async def resolve_verdicts_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("failed_fatal", "failed_partial", "inconclusive"):
            return state

        scan_id = state["scan_id"]
        logger.info("[resolve_verdicts] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "resolve_failed"}

        target = engine._create_target(scan)
        resolver = VerdictResolver()
        findings: list[Finding] = []
        resolved_verdicts_list = []
        results_for_test_run = []

        existing_findings = engine._repos.findings.list_for_scan(scan_id)
        det_map = {d["run_id"]: d for d in state.get("deterministic_evidence", [])}
        sem_map = {s["run_id"]: s for s in state.get("semantic_judgments", [])}

        for item in state.get("attack_results", []):
            run_id = item["run_id"]
            case_id = item["attack_id"]
            case = load_catalog_case(case_id)
            transcript = engine._repos.runs.get_transcript(run_id)
            if not case:
                continue

            # Reconstruct RuleResult
            det_data = det_map.get(run_id)
            rule_result = (
                RuleResult(
                    label=FindingLabel(det_data["label"]),
                    signals=det_data["signals"],
                )
                if det_data
                else None
            )

            # Reconstruct LlmJudgeResult
            sem_data = sem_map.get(run_id)
            llm_result = (
                LlmJudgeResult(
                    label=FindingLabel(sem_data["label"]),
                    confidence=sem_data["confidence"],
                    reason=sem_data["reason"],
                    model_name=sem_data.get("model_name", ""),
                    prompt_version="1.0",
                )
                if sem_data
                else None
            )

            verdict = resolver.resolve(
                scan_id, run_id, rule_result, llm_result, transcript, case=case
            )
            engine._repos.runs.save_verdict(verdict)
            engine._emit(
                scan_id,
                EventKind.VERDICT_CREATED,
                {
                    "attack_id": case_id,
                    "label": verdict.final_label.value,
                    "graph_node": "resolve_verdicts",
                },
            )
            resolved_verdicts_list.append(verdict.model_dump())

            case_meta = _case_metadata(case)
            result_item = {
                **case_meta,
                "label": verdict.final_label.value,
                "attempt": item.get("attempt", 1),
                "signals": rule_result.signals if rule_result else [],
                "resolution": verdict.resolution.value,
            }
            results_for_test_run.append(result_item)

            if verdict.final_label in (
                FindingLabel.CONFIRMED_FAILURE,
                FindingLabel.LIKELY_FAILURE,
                FindingLabel.NEEDS_REVIEW,
            ):
                already_saved = any(f.attack_id == case_id for f in existing_findings)
                if already_saved:
                    finding = next(f for f in existing_findings if f.attack_id == case_id)
                    findings.append(finding)
                else:
                    from evaluator.judges.weakness import derive_weak_point

                    sys_prompt = ""
                    if hasattr(target, "fixtures_path") and target.fixtures_path:
                        try:
                            sys_prompt = (target.fixtures_path / "system-prompt.txt").read_text(encoding="utf-8")
                        except OSError:
                            sys_prompt = ""

                    weak_pt = derive_weak_point(
                        case=case,
                        verdict=verdict,
                        transcript=transcript,
                        system_prompt=sys_prompt,
                    )

                    finding_key = hashlib.sha256(f"{scan_id}:{case_id}".encode()).hexdigest()[:12]
                    finding = Finding(
                        finding_id=f"find_{finding_key}",
                        scan_id=scan_id,
                        attack_id=case_id,
                        category=case.category,
                        severity=case.severity,
                        label=verdict.final_label,
                        confidence=verdict.llm_result.confidence if verdict.llm_result else (
                            1.0 if verdict.final_label == FindingLabel.CONFIRMED_FAILURE else 0.5
                        ),
                        summary=f"{case.goal} — {verdict.resolution.value}",
                        evidence_refs=verdict.evidence_refs,
                        needs_review=verdict.final_label == FindingLabel.NEEDS_REVIEW,
                        weak_point=weak_pt,
                    )
                    engine._repos.findings.save(finding)
                    findings.append(finding)

        # Persist SECURITY_BEFORE TestRun if not already saved
        existing_before = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_BEFORE)
        if not existing_before and results_for_test_run:
            test_run = TestRun(
                test_run_id=f"tr_{uuid.uuid4().hex[:12]}",
                scan_id=scan_id,
                kind=TestRunKind.SECURITY_BEFORE,
                metrics={
                    "attack_success_rate": _rate(results_for_test_run),
                    "blocked_rate": _blocked(results_for_test_run),
                    "cases": len(results_for_test_run),
                    "phase": RunPhase.BEFORE.value,
                },
                results=results_for_test_run,
                created_at=utc_now(),
            )
            engine._persist_test_run(test_run)

        if not findings:
            not_eval_count = sum(
                1 for v in resolved_verdicts_list
                if v.get("final_label") == FindingLabel.NOT_EVALUATED.value
            )
            total_count = len(resolved_verdicts_list)
            if not_eval_count == total_count and total_count > 0:
                logger.warning("Scan %s: all cases not_evaluated -> failed_partial", scan_id)
                await engine._fail(scan_id, ScanStatus.FAILED_PARTIAL)
                return {
                    "resolved_verdicts": resolved_verdicts_list,
                    "confirmed_findings": [],
                    "status": "failed_partial",
                    "phase": "all_cases_not_evaluated",
                    "errors": state.get("errors", [])
                    + ["All attack cases could not be evaluated (target unreachable or dropped)."],
                }
            if not_eval_count > 0:
                logger.warning(
                    "Scan %s: %d/%d cases not_evaluated -> completed_with_limitations",
                    scan_id,
                    not_eval_count,
                    total_count,
                )
                engine._set_status(scan_id, ScanStatus.COMPLETED_WITH_LIMITATIONS, 1.0)
                engine._emit(
                    scan_id,
                    EventKind.SCAN_COMPLETED,
                    {"status": "completed_with_limitations", "graph_node": "resolve_verdicts"},
                )
                return {
                    "resolved_verdicts": resolved_verdicts_list,
                    "confirmed_findings": [],
                    "status": "completed_with_limitations",
                    "phase": "completed_with_limitations",
                }

            logger.info("Scan %s produced 0 findings -> completing without hardening", scan_id)
            engine._set_status(scan_id, ScanStatus.COMPLETED, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_COMPLETED,
                {"status": "completed_no_findings", "graph_node": "resolve_verdicts"},
            )
            return {
                "resolved_verdicts": resolved_verdicts_list,
                "confirmed_findings": [],
                "status": "completed",
                "phase": "no_findings_completed",
            }

        return {
            "resolved_verdicts": resolved_verdicts_list,
            "confirmed_findings": [f.model_dump() for f in findings],
            "phase": "verdicts_resolved",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 7. generate_hardening_proposal
    # ──────────────────────────────────────────────────────────────────────────
    async def generate_hardening_proposal_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in (
            "completed",
            "completed_with_limitations",
            "failed_fatal",
            "failed_partial",
            "inconclusive",
        ):
            return state

        scan_id = state["scan_id"]
        logger.info("[generate_hardening_proposal] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "proposal_failed"}

        target = engine._create_target(scan)
        if getattr(target, "mode", None) == "evaluation_only":
            engine._set_status(scan_id, ScanStatus.COMPLETED_WITHOUT_RETEST, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_COMPLETED,
                {
                    "status": "completed_without_retest",
                    "reason": "External target is evaluation_only; remote hardening cannot be applied without an authorized staging contract.",
                    "graph_node": "generate_hardening_proposal",
                },
            )
            return {
                "status": "completed_without_retest",
                "phase": "completed_without_retest",
            }

        engine._set_status(scan_id, ScanStatus.HARDENING_PROPOSED, 0.70)

        proposal = engine._repos.proposals.latest_for_scan(scan_id)
        if not proposal:
            original_prompt = ""
            if hasattr(target, "fixtures_path") and target.fixtures_path:
                try:
                    original_prompt = (target.fixtures_path / "system-prompt.txt").read_text(encoding="utf-8")
                except OSError:
                    original_prompt = "You are a customer assistant endpoint."
            else:
                original_prompt = "You are a customer assistant endpoint."

            hardener = PromptHardener()
            _hardened_p, diff = hardener.propose(original_prompt)

            findings_objs = [
                Finding(**f) for f in state.get("confirmed_findings", [])
            ] or engine._repos.findings.list_for_scan(scan_id)

            compiler = PolicyCompiler()
            candidate = compiler.compile(findings_objs)

            orig_policy = {}
            if hasattr(target, "fixtures_path") and target.fixtures_path:
                try:
                    orig_policy = json.loads(
                        (target.fixtures_path / "vulnerable-policy.json").read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError):
                    orig_policy = {}

            p_diff = compiler.diff(orig_policy, candidate)

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
                affected_cases=[f.attack_id for f in findings_objs],
                risks=[
                    "Hardened prompt may reduce assistant helpfulness on edge cases.",
                    "Refund conditions may block legitimate refunds without verification.",
                ],
            )
            validator = ProposalValidator()
            validator.validate_or_raise(proposal)
            engine._repos.proposals.save(proposal)
            engine._emit(
                scan_id,
                EventKind.HARDENING_PROPOSED,
                {
                    "proposal_id": proposal.proposal_id,
                    "has_policy": candidate is not None,
                    "graph_node": "generate_hardening_proposal",
                },
            )

        engine._set_status(scan_id, ScanStatus.AWAITING_APPROVAL, 0.75)
        return {
            "hardening_proposal": proposal.model_dump(),
            "approval_status": "awaiting_approval",
            "phase": "awaiting_approval",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 8. human_approval_interrupt
    # ──────────────────────────────────────────────────────────────────────────
    async def human_approval_interrupt_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("completed", "completed_without_retest", "inconclusive", "failed_partial", "failed_fatal"):
            return state

        scan_id = state["scan_id"]
        logger.info("[human_approval_interrupt] scan_id=%s", scan_id)
        proposal_dict = state.get("hardening_proposal") or {}
        proposal_id = proposal_dict.get("proposal_id", "")

        existing_appr = engine._repos.approvals.get_for_proposal(proposal_id) if proposal_id else None

        if existing_appr is not None:
            approved = existing_appr.approved
            decision = existing_appr.decision
        else:
            logger.info("Pausing scan %s at human approval interrupt gate...", scan_id)
            resume_data = interrupt({
                "scan_id": scan_id,
                "proposal_id": proposal_id,
                "status": "awaiting_approval",
                "graph_node": "human_approval_interrupt",
            })

            logger.info("Scan %s resumed from interrupt with: %s", scan_id, resume_data)
            if isinstance(resume_data, dict):
                approved = bool(resume_data.get("approved", False))
                approved_by = str(resume_data.get("approved_by", "reviewer"))
                decision = str(resume_data.get("decision", "approved" if approved else "rejected"))
                comment = str(resume_data.get("comment", ""))
            else:
                approved = bool(resume_data)
                approved_by = "reviewer"
                decision = "approved" if approved else "rejected"
                comment = ""

            existing_appr = engine._repos.approvals.get_for_proposal(proposal_id) if proposal_id else None
            if not existing_appr and proposal_id:
                p_content = f"{proposal_dict.get('prompt_diff', '')}:{proposal_dict.get('policy_diff', '')}:{proposal_dict.get('rationale', '')}"
                p_hash = hashlib.sha256(p_content.encode("utf-8")).hexdigest()[:16]
                appr = Approval(
                    approval_id=f"appr_{uuid.uuid4().hex[:12]}",
                    proposal_id=proposal_id,
                    scan_id=scan_id,
                    approved=approved,
                    approved_by=approved_by,
                    proposal_hash=p_hash,
                    decision=decision,
                    created_at=utc_now(),
                )
                engine._repos.approvals.save(appr)
                engine._emit(
                    scan_id,
                    EventKind.APPROVAL_RECEIVED,
                    {
                        "proposal_id": proposal_id,
                        "approved": approved,
                        "approved_by": approved_by,
                        "decision": decision,
                        "proposal_hash": p_hash,
                        "comment": comment,
                        "graph_node": "human_approval_interrupt",
                    },
                )

        if not approved:
            logger.info("Proposal rejected for scan %s -> completed_without_retest", scan_id)
            engine._set_status(scan_id, ScanStatus.COMPLETED_WITHOUT_RETEST, 1.0)
            return {
                "approval_status": "rejected",
                "approval_metadata": {"approved": False, "decision": decision},
                "status": "completed_without_retest",
                "phase": "rejection_handled",
            }

        logger.info("Proposal approved for scan %s -> retesting", scan_id)
        engine._set_status(scan_id, ScanStatus.RETESTING, 0.80)
        engine._emit(
            scan_id,
            EventKind.RETEST_STARTED,
            {"proposal_id": proposal_id, "graph_node": "human_approval_interrupt"},
        )
        return {
            "approval_status": "approved",
            "approval_metadata": {"approved": True, "decision": decision},
            "phase": "approval_confirmed",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 9. retest_security
    # ──────────────────────────────────────────────────────────────────────────
    async def retest_security_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("completed", "completed_without_retest", "inconclusive", "failed_partial", "failed_fatal"):
            return state

        scan_id = state["scan_id"]
        logger.info("[retest_security] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "retest_failed"}

        existing_after = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_AFTER)
        if existing_after:
            after_run = existing_after[-1]
            return {
                "security_retest_results": after_run.results,
                "phase": "security_retested",
            }

        proposal = engine._repos.proposals.latest_for_scan(scan_id)
        if not proposal:
            await engine._fail(scan_id, ScanStatus.FAILED_PARTIAL)
            return {"status": "failed_partial", "errors": state.get("errors", []) + ["No proposal to retest"]}

        target = engine._create_target(scan)
        await target.apply_temporary_policy(
            proposal.policy_candidate, proposal.prompt_diff and _hardened_prompt(proposal)
        )
        profile = await target.profile()
        judge_ctx = _get_judge_context(target, profile)
        budget = BudgetTracker(budget=scan.config.budget)
        semantic_judge = (
            SemanticJudge(engine._model_client, budget, engine._model_name)
            if engine._model_client is not None and budget.budget.max_model_calls > 0
            else None
        )
        runner = SecurityRegressionRunner(judge_ctx, budget, semantic_judge=semantic_judge)
        cases = engine._select_cases(scan)
        after_run, after_verdicts = await runner.run_security(target, cases, scan_id, RunPhase.AFTER)
        engine._persist_test_run(after_run)

        for case, run_id, verdict, transcript in after_verdicts:
            engine._repos.db.execute(
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
                engine._repos.runs.save_transcript(transcript, run_id)
            engine._repos.runs.save_verdict(verdict)

        return {
            "security_retest_results": after_run.results,
            "phase": "security_retested",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 10. retest_benign_utility
    # ──────────────────────────────────────────────────────────────────────────
    async def retest_benign_utility_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("completed", "completed_without_retest", "inconclusive", "failed_partial", "failed_fatal"):
            return state

        scan_id = state["scan_id"]
        logger.info("[retest_benign_utility] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "failed_fatal", "phase": "utility_failed"}

        existing_utility = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.UTILITY)
        if existing_utility:
            utility_run = existing_utility[-1]
            return {
                "benign_utility_results": utility_run.results,
                "phase": "benign_utility_retested",
            }

        target = engine._create_target(scan)
        proposal = engine._repos.proposals.latest_for_scan(scan_id)
        if proposal:
            await target.apply_temporary_policy(
                proposal.policy_candidate, proposal.prompt_diff and _hardened_prompt(proposal)
            )

        utility_runner = UtilityRegressionRunner()
        benign_cases = engine._planner.load_benign_cases()
        utility_run = await utility_runner.run_utility(target, benign_cases, scan_id)
        engine._persist_test_run(utility_run)

        return {
            "benign_utility_results": utility_run.results,
            "phase": "benign_utility_retested",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 11. calculate_metrics
    # ──────────────────────────────────────────────────────────────────────────
    async def calculate_metrics_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("failed_fatal", "failed_partial"):
            return state

        scan_id = state["scan_id"]
        logger.info("[calculate_metrics] scan_id=%s", scan_id)

        before_runs = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_BEFORE)
        after_runs = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_AFTER)
        utility_runs = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.UTILITY)
        baseline_runs = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.UTILITY_BEFORE)

        before_rate = before_runs[-1].metrics.get("attack_success_rate", 0.0) if before_runs else 0.0
        after_rate = after_runs[-1].metrics.get("attack_success_rate", 0.0) if after_runs else 0.0
        benign_rate = utility_runs[-1].metrics.get("benign_success_rate", 1.0) if utility_runs else 1.0
        baseline_rate = baseline_runs[-1].metrics.get("benign_success_rate", 1.0) if baseline_runs else 1.0

        over_refusal_delta = max(0.0, baseline_rate - benign_rate)

        if state.get("status") == "inconclusive":
            classification = "inconclusive"
        elif after_runs:
            if after_rate == 0.0 and benign_rate >= 0.75:
                classification = "verified_mitigation"
            elif after_rate < before_rate:
                classification = "partial_mitigation"
            else:
                classification = "still_vulnerable"
        else:
            classification = "inconclusive" if state.get("status") == "inconclusive" else "not_retested"

        computed_metrics = {
            "attack_success_rate_before": before_rate,
            "attack_success_rate_after": after_rate,
            "benign_success_rate": benign_rate,
            "baseline_benign_success_rate": baseline_rate,
            "over_refusal_delta": over_refusal_delta,
            "classification": classification,
        }

        return {
            "metrics": computed_metrics,
            "phase": "metrics_calculated",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 12. promote_regressions
    # ──────────────────────────────────────────────────────────────────────────
    async def promote_regressions_node(state: RavenScanState) -> dict[str, Any]:
        if state.get("status") in ("completed_without_retest", "inconclusive", "failed_fatal", "failed_partial"):
            return state

        scan_id = state["scan_id"]
        logger.info("[promote_regressions] scan_id=%s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return state

        after_runs = engine._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_AFTER)
        if after_runs:
            await engine._save_regressions(scan_id, scan.target.target_id, after_runs[-1])

        active_regs = engine._repos.regressions.list_active(scan.target.target_id)
        reg_ids = [r["attack_case_id"] for r in active_regs]
        return {
            "regression_case_ids": reg_ids,
            "phase": "regressions_promoted",
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 13. generate_reports
    # ──────────────────────────────────────────────────────────────────────────
    async def generate_reports_node(state: RavenScanState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        logger.info("[generate_reports] scan_id=%s", scan_id)

        # Idempotent report generation
        result = generate_report(engine._repos, scan_id)
        rows = engine._repos.db.query_all("SELECT artifact_id FROM report_artifacts WHERE scan_id = ?", (scan_id,))
        art_ids = [str(r["artifact_id"]) for r in rows] or [result.artifact_id]

        status_in_state = state.get("status", "completed")
        if status_in_state == "completed_without_retest":
            engine._set_status(scan_id, ScanStatus.COMPLETED_WITHOUT_RETEST, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_COMPLETED,
                {"status": "completed_without_retest", "graph_node": "generate_reports"},
            )
        elif status_in_state == "completed_with_limitations":
            engine._set_status(scan_id, ScanStatus.COMPLETED_WITH_LIMITATIONS, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_COMPLETED,
                {"status": "completed_with_limitations", "graph_node": "generate_reports"},
            )
        elif status_in_state == "inconclusive":
            engine._set_status(scan_id, ScanStatus.INCONCLUSIVE, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_COMPLETED,
                {"status": "inconclusive", "graph_node": "generate_reports"},
            )
        elif status_in_state == "failed_fatal":
            engine._set_status(scan_id, ScanStatus.FAILED_FATAL, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_FAILED,
                {"status": "failed_fatal", "graph_node": "generate_reports"},
            )
        elif status_in_state == "failed_partial":
            engine._set_status(scan_id, ScanStatus.FAILED_PARTIAL, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_FAILED,
                {"status": "failed_partial", "graph_node": "generate_reports"},
            )
        else:
            engine._set_status(scan_id, ScanStatus.COMPLETED, 1.0)
            engine._emit(
                scan_id,
                EventKind.SCAN_COMPLETED,
                {"status": "completed", "graph_node": "generate_reports"},
            )

        return {
            "report_artifact_ids": art_ids,
            "phase": "completed",
            "status": engine._repos.scans.get(scan_id).status.value,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Graph Topology: Add Nodes
    # ──────────────────────────────────────────────────────────────────────────
    workflow.add_node("initialize_scan", initialize_scan_node)
    workflow.add_node("recon", recon_node)
    workflow.add_node("plan_attacks", plan_attacks_node)
    workflow.add_node("execute_security_tests", execute_security_tests_node)
    workflow.add_node("judge_results", judge_results_node)
    workflow.add_node("resolve_verdicts", resolve_verdicts_node)
    workflow.add_node("generate_hardening_proposal", generate_hardening_proposal_node)
    workflow.add_node("human_approval_interrupt", human_approval_interrupt_node)
    workflow.add_node("retest_security", retest_security_node)
    workflow.add_node("retest_benign_utility", retest_benign_utility_node)
    workflow.add_node("calculate_metrics", calculate_metrics_node)
    workflow.add_node("promote_regressions", promote_regressions_node)
    workflow.add_node("generate_reports", generate_reports_node)

    # ──────────────────────────────────────────────────────────────────────────
    # Graph Topology: Edges & Routing
    # ──────────────────────────────────────────────────────────────────────────
    workflow.add_edge(START, "initialize_scan")

    def route_after_init(state: RavenScanState) -> str:
        if state.get("status") == "failed_fatal":
            return "generate_reports"
        return "recon"

    workflow.add_conditional_edges(
        "initialize_scan",
        route_after_init,
        {"generate_reports": "generate_reports", "recon": "recon"},
    )

    def route_after_recon(state: RavenScanState) -> str:
        if state.get("status") in ("failed_fatal", "failed_partial"):
            return "generate_reports"
        return "plan_attacks"

    workflow.add_conditional_edges(
        "recon",
        route_after_recon,
        {"generate_reports": "generate_reports", "plan_attacks": "plan_attacks"},
    )

    def route_after_plan(state: RavenScanState) -> str:
        if state.get("status") in ("failed_fatal", "failed_partial"):
            return "generate_reports"
        if state.get("status") == "inconclusive":
            return "calculate_metrics"
        return "execute_security_tests"

    workflow.add_conditional_edges(
        "plan_attacks",
        route_after_plan,
        {
            "generate_reports": "generate_reports",
            "calculate_metrics": "calculate_metrics",
            "execute_security_tests": "execute_security_tests",
        },
    )

    def route_after_execute(state: RavenScanState) -> str:
        if state.get("status") in ("failed_fatal", "failed_partial"):
            return "generate_reports"
        return "judge_results"

    workflow.add_conditional_edges(
        "execute_security_tests",
        route_after_execute,
        {"generate_reports": "generate_reports", "judge_results": "judge_results"},
    )

    def route_after_judge(state: RavenScanState) -> str:
        if state.get("status") in ("failed_fatal", "failed_partial"):
            return "generate_reports"
        return "resolve_verdicts"

    workflow.add_conditional_edges(
        "judge_results",
        route_after_judge,
        {"generate_reports": "generate_reports", "resolve_verdicts": "resolve_verdicts"},
    )

    def route_after_resolve(state: RavenScanState) -> str:
        if state.get("status") in (
            "completed",
            "completed_with_limitations",
            "failed_fatal",
            "failed_partial",
        ):
            return "generate_reports"
        return "generate_hardening_proposal"

    workflow.add_conditional_edges(
        "resolve_verdicts",
        route_after_resolve,
        {
            "generate_reports": "generate_reports",
            "generate_hardening_proposal": "generate_hardening_proposal",
        },
    )

    def route_after_hardening(state: RavenScanState) -> str:
        if state.get("status") in ("completed_without_retest", "failed_fatal", "failed_partial"):
            return "generate_reports"
        return "human_approval_interrupt"

    workflow.add_conditional_edges(
        "generate_hardening_proposal",
        route_after_hardening,
        {
            "generate_reports": "generate_reports",
            "human_approval_interrupt": "human_approval_interrupt",
        },
    )

    def route_after_approval(state: RavenScanState) -> str:
        if state.get("approval_status") == "rejected" or state.get("status") == "completed_without_retest":
            return "generate_reports"
        return "retest_security"

    workflow.add_conditional_edges(
        "human_approval_interrupt",
        route_after_approval,
        {"generate_reports": "generate_reports", "retest_security": "retest_security"},
    )

    def route_after_security_retest(state: RavenScanState) -> str:
        if state.get("status") in ("failed_fatal", "failed_partial"):
            return "generate_reports"
        return "retest_benign_utility"

    workflow.add_conditional_edges(
        "retest_security",
        route_after_security_retest,
        {
            "generate_reports": "generate_reports",
            "retest_benign_utility": "retest_benign_utility",
        },
    )

    workflow.add_edge("retest_benign_utility", "calculate_metrics")

    def route_after_metrics(state: RavenScanState) -> str:
        if state.get("status") in ("inconclusive", "failed_fatal", "failed_partial"):
            return "generate_reports"
        return "promote_regressions"

    workflow.add_conditional_edges(
        "calculate_metrics",
        route_after_metrics,
        {"generate_reports": "generate_reports", "promote_regressions": "promote_regressions"},
    )

    workflow.add_edge("promote_regressions", "generate_reports")
    workflow.add_edge("generate_reports", END)

    return workflow.compile(checkpointer=checkpointer)
